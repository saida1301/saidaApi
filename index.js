import { BlobServiceClient } from "@azure/storage-blob";
import multer, { diskStorage } from "multer";
import { v4 as uuidv4 } from "uuid";
import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cors from "cors";
import nodemailer from "nodemailer";
const app = express();

const pool = mysql.createPool({
  connectionLimit: 10,
  host: "145.14.156.192",
  user: "u983993164_1is",
  password: "Buta2023@",
  database: "u983993164_1is",
  timeout: 100000,
});

pool.getConnection((err, connection) => {
  if (err) {
    console.error("Error connecting to database: " + err.stack);
    return;
  }

  console.log("Connected to database with ID " + connection.threadId);

  // Release the connection when you're done with it.
  connection.release();
});
app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

const connectionString =
  "DefaultEndpointsProtocol=https;AccountName=ismobile;AccountKey=0vW600nc8IHVC3tPsRoHCBh6Zx/zHvRDx2H/wnmsl+w7WGq9c8plB5ws6E9qI6ZP2m05xwm/wrC8+AStRLo2FA==;EndpointSuffix=core.windows.net";
const blobServiceClient =
  BlobServiceClient.fromConnectionString(connectionString);

const containerName = "mobileapp";
const containerClient = blobServiceClient.getContainerClient(containerName);

// Configure multer for file uploads
const storage = diskStorage({
  destination: "uploads/",
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + uuidv4();
    const extension = file.originalname.split(".").pop();
    let filePath = "";
    if (file.fieldname === "image") {
      filePath = "back/assets/images/cv_photo/" + uniqueSuffix + "." + extension;
    } else if (file.fieldname === "cv") {
      filePath = "back/assets/images/cvs/" + uniqueSuffix + "." + extension;
    }
    cb(null, uniqueSuffix + "." + extension, filePath);
  },
});

const upload = multer({ storage });

const uploadToBlobStorage = async (file, folderName = 'trainings') => {
  const fileName = folderName + '/' + Date.now() + '_' + file.originalname; // Include the folder name as part of the blob name
  const blockBlobClient = containerClient.getBlockBlobClient(fileName);
  await blockBlobClient.uploadFile(file.path);

  const fileUrl = `https://${containerName}.blob.core.windows.net/${fileName}`;
  return fileUrl;
};




// app.use(passport.initialize());


app.post("/login", (req, res) => {
  const { email, password } = req.body;
  pool.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
        res.status(500).json({ message: "Internal server error" });
        return;
      }

      if (results.length === 0) {
        res.status(401).json({ message: "Email or password is incorrect" });
        return;
      }

      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          console.log(err);
          res.status(500).json({ message: "Internal server error" });
          return;
        }

        if (!isMatch) {
          res.status(401).json({ message: "Email or password is incorrect" });
          return;
        }

        const token = jwt.sign({ id: user.id }, "secret", { expiresIn: "1h" });
        res.json({ token });
      });
    }
  );
});

app.post("/signup", (req, res) => {
  const { name, email, password } = req.body;

  pool.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
        res.status(500).json({ message: "Internal server error" });
        return;
      }

      if (results.length > 0) {
        res.status(400).json({ message: "Email already in use" });
        return;
      }

      bcrypt.genSalt(10, (err, salt) => {
        if (err) {
          console.log(err);
          res.status(500).json({ message: "Internal server error" });
          return;
        }

        bcrypt.hash(password, salt, (err, hash) => {
          if (err) {
            console.log(err);
            res.status(500).json({ message: "Internal server error" });
            return;
          }

          pool.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hash],
            (err, results) => {
              if (err) {
                console.log(err);
                res.status(500).json({ message: "Internal server error" });
                return;
              }

              const token = jwt.sign({ id: results.insertId }, "secret", {
                expiresIn: "1h",
              });
              res.json({ token });
            }
          );
        });
      });
    }
  );
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "Logout successful" });
});

app.post('/contact', async (req, res) => {
  try {
    const { name, surname, email, phone, message } = req.body;

    const query = `
      INSERT INTO contact (name, surname, email, phone, message, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, NOW(), NOW())
    `;

    pool.query(query, [name, surname, email, phone, message]);

    let transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'humbeteliyevaseide2001@gmail.com',
        pass: 'nwudhimwttuqdzxv'
      }
    });

    const mailOptions = {
      from:req.body.email,
      to: 'humbesaida@gmail.com',
      subject: 'New Message from Contact Form',
      text: `Name: ${name}\nSurname: ${surname}\nEmail: ${email}\nPhone: ${phone}\nMessage: ${message}`,
    };

    transport.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ error: 'An error occurred while sending the email.' });
      } else {
        console.log('Email sent:', info.response);
        res.status(200).json({ message: 'Contact message saved and email sent successfully.' });
      }
    });
  } catch (err) {
    console.error('Error saving contact message:', err);
    res.status(500).json({ error: 'An error occurred while saving the contact message.' });
  }
});

// app.post('/logout', (req, res) => {
//   const token = req.headers.authorization.split(' ')[1];

//   jwt.verify(token, "secret", (err, decoded) => {
//     if (err) {
//       res.status(401).json({ error: 'Invalid token' });
//     } else {
//       const userId = decoded.id;

//       pool.query('UPDATE users SET token = null WHERE id = ?', [userId], (err, result) => {
//         if (err) {
//           res.status(500).json({ error: 'Internal server error' });
//         } else {
//           res.status(200).json({ message: 'Logout successful' });
//         }
//       });
//     }
//   });
// });
app.post('/vacancies/:id/view', (req, res) => {
  const vacancyId = req.params.id;

  pool.query('UPDATE vacancies SET view = view + 1 WHERE id = ?', [vacancyId], (error, results) => {
    if (error) {
      console.error('Failed to increment view count:', error);
      res.sendStatus(500);
    } else {
      res.sendStatus(200);
    }
  });
});
app.post('/blogs/:id/view', (req, res) => {
  const blogId = req.params.id;

  pool.query('UPDATE blogs SET view = view + 1 WHERE id = ?', [vacancyId], (error, results) => {
    if (error) {
      console.error('Failed to increment view count:', error);
      res.sendStatus(500);
    } else {
      res.sendStatus(200);
    }
  });
});
app.post('/companies/:id/view', (req, res) => {
  const companyId = req.params.id;

  pool.query('UPDATE companies SET view = view + 1 WHERE id = ?', [vacancyId], (error, results) => {
    if (error) {
      console.error('Failed to increment view count:', error);
      res.sendStatus(500);
    } else {
      res.sendStatus(200);
    }
  });
});
app.post('/trainings/:id/view', (req, res) => {
  const telimId = req.params.id;

  pool.query('UPDATE trainings SET view = view + 1 WHERE id = ?', [vacancyId], (error, results) => {
    if (error) {
      console.error('Failed to increment view count:', error);
      res.sendStatus(500);
    } else {
      res.sendStatus(200);
    }
  });
});
app.post('/cv/:id/view', (req, res) => {
  const cvId = req.params.id;

  pool.query('UPDATE cv SET view = view + 1 WHERE id = ?', [vacancyId], (error, results) => {
    if (error) {
      console.error('Failed to increment view count:', error);
      res.sendStatus(500);
    } else {
      res.sendStatus(200);
    }
  });
});
app.get("/user/:userId", (req, res) => {
  const userId = req.params.userId;
  const query = "SELECT * FROM users WHERE id = ?";
  pool.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error retrieving user: " + err.stack);
      res.status(500).send("Error retrieving user");
      return;
    }

    if (results.length === 0) {
      res.status(404).send("User not found");
      return;
    }

    const user = results[0];
    res.send(user);
  });
});

app.post('/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  const getUserQuery = `SELECT * FROM users WHERE email = ?`;
  pool.query(getUserQuery, [email], async (error, results) => {
    if (error) {
      console.error(error);
      res.status(500).send('Error querying database');
      return;
    }

    if (results.length === 0) {
      res.status(401).send('User not found');
      return;
    }

    const user = results[0];

    const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);
    if (!isOldPasswordCorrect) {
      res.status(401).send('Incorrect old password');
      return;
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatePasswordQuery = `UPDATE users SET password = ? WHERE email = ?`;
    pool.query(updatePasswordQuery, [hashedNewPassword, email], (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).send('Error updating password');
        return;
      }

      res.status(200).send('Password updated successfully');
    });
  });
});
app.post("/rating", async (req, res) => {
  try {
    const { review_id, rating } = req.body;
    pool.query(
      "INSERT INTO rating (review_id, rating,created_at, updated_at) VALUES (?, ?,NOW(), NOW()) ON DUPLICATE KEY UPDATE rating = ?",
      [review_id, rating, rating],
      (error, results, fields) => {
        if (error) {
          console.log(error);
          res.sendStatus(500);
        } else {
          console.log(`rating added`);
          res.sendStatus(201);
        }
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/ratings", async (req, res) => {
  try {
    pool.query("SELECT * FROM rating ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/accept", async (req, res) => {
  try {
    pool.query("SELECT * FROM accept_type ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/gender", async (req, res) => {
  try {
    pool.query("SELECT * FROM gender ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/job", async (req, res) => {
  try {
    pool.query("SELECT * FROM job_type ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/vacancies", async (req, res) => {
  try {
    pool.query("SELECT * FROM vacancies ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/cv", async (req, res) => {
  try {
    pool.query("SELECT * FROM cv ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.put('/vacancies/:id', async (req, res) => {
  const vacancyId = req.params.id;

  try {
    const query = 'UPDATE vacancies SET status = 0 WHERE id = ?';
    const result = await pool.query(query, [vacancyId]);

    if (result.affectedRows > 0) {
      res.status(200).json({ message: 'Vacancy status updated successfully' });
    } else {
      res.status(404).json({ message: 'Vacancy not found' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating vacancy status' });
  }
});

app.get("/favancie", async (req, res) => {
  try {
    pool.query("SELECT * FROM favorits", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/user", async (req, res) => {
  try {
    pool.query("SELECT * FROM users", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/cities", async (req, res) => {
  try {
    pool.query("SELECT * FROM cities", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/experiences", async (req, res) => {
  try {
    pool.query("SELECT * FROM experiences", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get('/trainings/similar/:title', async (req, res) => {
  const title = req.params.title;
  const query = "SELECT * FROM trainings WHERE title LIKE CONCAT('%', ?, '%')";
  const values = [title];

  pool.query(query, values, (error, results) => {
    if (error) {
      console.error(error);
      res.status(500).json({ message: 'Error getting similar trainings' });
    } else {
      res.status(200).json({ trainings: results });
    }
  });
});

app.get("/educations", async (req, res) => {
  try {
    pool.query("SELECT * FROM educations", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.use("/vacancies/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM vacancies WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/companies", async (req, res) => {
  try {
    pool.query("SELECT * FROM companies ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.use("/companies/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM companies WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/sectors", async (req, res) => {
  try {
    pool.query("SELECT * FROM sectors", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.use("/sectors/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM sectors WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/categories", async (req, res) => {
  try {
    pool.query("SELECT * FROM categories", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.post('/companies', async (req, res) => {
  try {
    const companyData = req.body;

   
    const query = 'INSERT INTO companies SET ?';
    await pool.query(query, companyData);

    res.status(201).json({ message: 'Company added successfully' });
  } catch (error) {
    console.error('Error adding company:', error);
    res.status(500).json({ error: 'Failed to add company' });
  }
});

app.use("/categories/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM categories WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});




app.get("/vacancy/:companyId", (req, res) => {
  const { companyId } = req.params;

  const sql = `SELECT * FROM vacancies WHERE company_id IN (SELECT id FROM companies WHERE id = ${companyId})`;

  pool.query(sql, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving favorites");
    }

    return res.json(results);
  });
});

app.get("/trainings", async (req, res) => {
  try {
    pool.query("SELECT * FROM trainings WHERE status = '1' ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});



app.use("/trainings/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM trainings WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});



// Function to upload image to Azure Blob Storage
// const uploadToBlobStorage = async (file) => {
//   const fileName = 'trainings/' + Date.now() + '_' + file.originalname; // Include 'trainings/' as part of the blob name
//   const blockBlobClient = containerClient.getBlockBlobClient(fileName);
//   await blockBlobClient.uploadFile(file.path);
//   return fileName;
// };



app.post('/trainings',cors(), upload.single('image'), async (req, res) => {
  const { user_id, company_id, title, about, price, redirect_link, deadline } = req.body;
  const imagePath = req.file ? req.file.path : null;

  try {
    let imageUrl = null;

  // Check if file was uploaded
  if (imagePath) {
    // Upload the image to Azure Blob Storage
    const uploadedFileName = await uploadToBlobStorage(req.file);
    imageUrl = `back/assets/images/trainings/${uploadedFileName}`;
  }

    const query = `INSERT INTO trainings (user_id, company_id, title, about, price, redirect_link, image, deadline, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;
    const values = [user_id, company_id, title, about, price, redirect_link, imageUrl, deadline];

    // Execute the database query
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error adding training' });
      } else {
        res.status(201).json({ message: 'Training added successfully' });
      }
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Error uploading image' });
  }
});
app.get("/training/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM trainings WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving trainings");
    }

    return res.json(results);
  });
});



app.post('/vacancies', async (req, res) => {
  try {
    const vacancyData = req.body;
    const position = vacancyData.position;
    const slug = position.toLowerCase().replace(/\s+/g, '-');
    vacancyData.slug = slug;
    const query = 'INSERT INTO vacancies SET ?';
    await pool.query(query, vacancyData);
    res.status(201).json({ message: 'Vacancy added successfully' });
  } catch (error) {
    console.error('Error adding vacancy:', error);
    res.status(500).json({ error: 'Failed to add vacancy' });
  }
});





app.get("/vacancie/:categoryId", (req, res) => {
  const { categoryId } = req.params;

  const sql = `SELECT * FROM vacancies WHERE category_id IN (SELECT id FROM categories WHERE id = ${categoryId})`;

  pool.query(sql, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving favorites");
    }

    return res.json(results);
  });
});

app.get("/reviews/:companyId", async (req, res) => {
  try {
    const { companyId } = req.params;
    pool.query("SELECT * FROM review WHERE company_id = ?", [companyId], (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});


app.post("/reviews", async (req, res) => {
    try {
      const { fullname, company_id, message  } = req.body;
      pool.query(
        "INSERT INTO review (fullname, company_id, message, created_at, updated_at)  VALUES (?, ?, ?, NOW(), NOW()) ",
        [fullname, company_id, message],
        (error, results, fields) => {
          if (error) throw error;
          console.log(`Review added`);
          res.sendStatus(201);
        }
      );
    } catch (error) {
      console.log(error);
      res.sendStatus(500);
    }
  });
app.get("/blogs", async (req, res) => {
  try {
    pool.query("SELECT * FROM blogs  ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.use("/blogs/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM blogs WHERE id = ?",
      [id],
      (error, results, fields) => {
        if (error) throw error;
        res.json(results);
      }
    );
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.post("/favorites", async (req, res) => {
  try {
    const { user_id , vacancy_id } = req.body;
    const query = "INSERT INTO favorits (user_id, vacancy_id) VALUES (?, ?)";
    pool.query(query, [user_id, vacancy_id], (error, results, fields) => {
      if (error) {
        console.error(error);
        res.sendStatus(500);
      } else {
        console.log(`Added to favorites`);
        res.sendStatus(201);
      }
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});

app.post("/favorite", async (req, res) => {
  try {
    const { user_id, cv_id } = req.body;

    const query = "INSERT INTO favorits (user_id, cv_id) VALUES (?, ?)";
    pool.query(query, [user_id, cv_id], (error, results, fields) => {
      if (error) {
        console.error(error);
        res.sendStatus(500);
      } else {
        console.log(`Added to favorites`);
        res.sendStatus(201);
      }
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
});


app.get("/favorites/:userId", (req, res) => {
  const { userId } = req.params;

  const sql = `SELECT * FROM vacancies WHERE id IN (SELECT vacancy_id FROM favorits WHERE user_id = ${userId})`;

  pool.query(sql, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving favorites");
    }

    return res.json(results);
  });
});

app.delete("/favorites/:user_id/:vacancy_id", (req, res) => {
  const { user_id, vacancy_id } = req.body;

  const sql = `DELETE FROM favorits WHERE user_id = ${user_id} AND movie_id = ${vacancy_id}`;

  pool.query(sql, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error removing from favorites");
    }

    return res.status(200).send("Item removed from favorites");
  });
});


app.post(
  '/cv', cors(),
  upload.fields([{ name: 'cv', maxCount: 1 }, { name: 'image', maxCount: 1 }]),
  async (req, res) => {
    const {
      user_id,
      category_id,
      city_id,
      education_id,
      experience_id,
      job_type_id,
      gender_id,
      name,
      surname,
      father_name,
      email,
      contact_phone,
      position,
      about_education,
      salary,
      birth_date,
      work_history,
      skills,
    } = req.body;

    try {
      const cvFile = req.files['cv'][0];
      const imageFile = req.files['image'][0];

      const cvUrl = await uploadToBlobStorage(cvFile, 'cv');
      const imageUrl = await uploadToBlobStorage(imageFile, 'cv');
      const portfolio = [
        {
          job_name: req.body['portfolio_job_name'],
          company: req.body['portfolio_company'],
          link: req.body['portfolio_link'],
        },
      ];

      // Create slug from lowercase name and surname combination
      const slug = `${name.toLowerCase()}-${surname.toLowerCase()}`.replace(/\s+/g, '-');

      const query =
        'INSERT INTO cv (user_id, category_id, city_id, education_id, experience_id, job_type_id, gender_id, name, surname, father_name, email, contact_phone, position, about_education, salary, birth_date, work_history, skills, cv, image, portfolio, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())';

      const values = [
        user_id,
        category_id,
        city_id,
        education_id,
        experience_id,
        job_type_id,
        gender_id,
        name,
        surname,
        father_name,
        email,
        contact_phone,
        position,
        about_education,
        salary,
        birth_date,
        work_history,
        skills,
        cvUrl,
        imageUrl,
        JSON.stringify({ portfolio }),
        slug,
      ];

      pool.query(query, values, (error, results) => {
        if (error) {
          console.error(error);
          res.status(500).json({ message: 'Error adding CV' });
        } else {
          res.status(201).json({ message: 'CV added successfully', imageUrl });
        }
      });
    } catch (error) {
      console.error('Error uploading CV:', error);
      res.status(500).json({ message: 'Error uploading CV' });
    }
  }
);


app.get('/cv/:id', (req, res) => {
  const { id } = req.params;

  pool.query('SELECT * FROM cv WHERE id = ?', [id], (error, results) => {
    if (error) {
      console.error(error);
      res.status(500).json({ message: 'Error retrieving CV information' });
    } else {
      if (results.length > 0) {
        const cv = results[0];
        res.status(200).json(cv);
      } else {
        res.status(404).json({ message: 'CV not found' });
      }
    }
  });
});


app.put('/ci/:id', upload.fields([{ name: 'cv', maxCount: 1 }, { name: 'image', maxCount: 1 }]), async (req, res) => {
  const { id } = req.params;

  const {
    category_id,
    city_id,
    education_id,
    experience_id,
    job_type_id,
    gender_id,
    name,
    surname,
    father_name,
    email,
    position,
    about_education,
    salary,
    birth_date,
    work_history,
    skills,
  } = req.body;
  console.log(category_id, city_id)
  try {
    const cvFile = req.files['cv'][0];
    const imageFile = req.files['image'][0];

    const cvUrl = await uploadToBlobStorage(cvFile, 'cv');
    const imageUrl = await uploadToBlobStorage(imageFile, 'cv');
    const portfolio = [
      {
        job_name: req.body['portfolio_job_name'],
        company: req.body['portfolio_company'],
        link: req.body['portfolio_link']
      }
    ];

    const query = `UPDATE cv SET category_id = ?, city_id = ?, education_id = ?, experience_id = ?, job_type_id = ?, gender_id = ?, name = ?, surname = ?, father_name = ?, email = ?, position = ?, about_education = ?, salary = ?, birth_date = ?, work_history = ?, skills = ?, cv = ?, image = ?, portfolio = ?, updated_at = NOW() WHERE id = ?`;

    const values = [
      category_id,
      city_id,
      education_id,
      experience_id,
      job_type_id,
      gender_id,
      name,
      surname,
      father_name,
      email,
      position,
      about_education,
      salary,
      birth_date,
      work_history,
      skills,
      cvUrl,
      imageUrl,
      JSON.stringify({ portfolio }),
      id
    ];

    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating CV' });
      } else {
        res.status(200).json({ message: 'CV updated successfully', imageUrl });
      }
    });
  } catch (error) {
    console.error('Error uploading CV:', error);
    res.status(500).json({ message: 'Error uploading CV' });
  }
});



app.listen(8000, () => {
  console.log(`Server is running on port 8000`);
});
