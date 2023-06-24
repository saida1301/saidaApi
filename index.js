import { BlobServiceClient } from "@azure/storage-blob";
import multer, { diskStorage } from "multer";
import { v4 as uuidv4 } from 'uuid';
import express from "express";
import session from "express-session";
import bodyParser from "body-parser";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import crypto from 'crypto';
import cors from "cors";
import nodemailer from "nodemailer";
import schedule from 'node-schedule';
import { body, validationResult } from 'express-validator';
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
  connection.release();
});


const connectionString =
 "DefaultEndpointsProtocol=https;AccountName=ismobile;AccountKey=0vW600nc8IHVC3tPsRoHCBh6Zx/zHvRDx2H/wnmsl+w7WGq9c8plB5ws6E9qI6ZP2m05xwm/wrC8+AStRLo2FA==;EndpointSuffix=core.windows.net";
const blobServiceClient =
  BlobServiceClient.fromConnectionString(connectionString);

const containerName = "mobileapp";
const containerClient = blobServiceClient.getContainerClient(containerName);


const storage = diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + uuidv4();
    const extension = file.originalname.split('.').pop();
    let filePath = '';
    if (file.fieldname === 'image') {
      filePath = 'back/assets/images/cv_photo/' + uniqueSuffix + '.' + extension;
    } else if (file.fieldname === 'cv') {
      filePath = 'back/assets/images/cvs/' + uniqueSuffix + '.' + extension;
    }
    cb(null, uniqueSuffix + '.' + extension, filePath);
  },
});

const upload = multer({ storage });
const uploadToBlobStorage = async (file, folderName = "trainings") => {
  const folder = "company"; // Specify the folder name
  const folderPath = folder + "/"; // Add a trailing slash to indicate a folder
  const fileName = folderPath + Date.now() + "_" + file.originalname; 
  const extension = file.originalname.split('.').pop();
  const contentType = mime.contentType(extension);

  const blockBlobClient = containerClient.getBlockBlobClient(fileName);
  await blockBlobClient.uploadFile(file.path, {
    blobHTTPHeaders: {
      blobContentType: contentType,
    },
  });

  const fileUrl = `https://${containerName}.blob.core.windows.net/${fileName}`;
  return fileUrl;
};

app.use(
  session({
    secret: "secret",
    resave: true,
    saveUninitialized: true,
  })
);


app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
          return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
          return res.status(401).json({ message: 'Email or password is incorrect' });
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) {
            console.log(err);
            return res.status(500).json({ message: 'Internal server error' });
          }

          if (!isMatch) {
            return res.status(401).json({ message: 'Email or password is incorrect' });
          }

          const token = jwt.sign({ id: user.id }, 'secret', { expiresIn: '1h' });
          return res.json({ token });
        });
      }
    );
  }
);

app.post(
  '/signup',
  [
    body('name').notEmpty(),
    body('surname').notEmpty(),
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty(),
    body('cat_id').isArray(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, surname, email, password, cat_id } = req.body;

    pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email],
      (err, results) => {
        if (err) {
          console.log(err);
          return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length > 0) {
          return res.status(400).json({ message: 'Email already in use' });
        }

        bcrypt.genSalt(10, (err, salt) => {
          if (err) {
            console.log(err);
            return res.status(500).json({ message: 'Internal server error' });
          }

          bcrypt.hash(password, salt, (err, hash) => {
            if (err) {
              console.log(err);
              return res.status(500).json({ message: 'Internal server error' });
            }

            const catIdsArray = Array.isArray(cat_id) ? cat_id : [cat_id];
            const catIdsJSON = JSON.stringify(catIdsArray);

            pool.query(
              'INSERT INTO users (name, surname, email, password, cat_id) VALUES (?, ?, ?, ?, ?)',
              [name, surname, email, hash, catIdsJSON],
              (err, results) => {
                if (err) {
                  console.log(err);
                  return res.status(500).json({ message: 'Internal server error' });
                }

                const token = jwt.sign({ id: results.insertId }, 'secret', {
                  expiresIn: '1h',
                });
                return res.json({ token, cat_id: catIdsArray }); // Include cat_id in the response
              }
            );
          });
        });
      }
    );
  }
);








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
app.get("/stories", async (req, res) => {
  try {
    pool.query("SELECT * FROM stories WHERE status = '1' ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
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

const weeklyVacancyJob = schedule.scheduleJob('0 0 * * 0', fetchWeeklyVacancies);


app.post('/vacancy', cors(), (req, res) => {
  const userId = req.body.userId;
  const startIndex = req.body.startIndex || 0; // Default startIndex to 0 if not provided

  // Retrieve the vacancies based on the userId and startIndex
  fetchLatestVacancies(userId, startIndex)
    .then(vacancies => {
      if (vacancies.length > 0) {
        res.json(vacancies);
      } else {
        res.json([]); // Return an empty array if no vacancies found
      }
    })
    .catch(error => res.status(500).json({ error: 'Internal server error' }));
});


function fetchWeeklyVacancies(userId) {
  return new Promise((resolve, reject) => {
    // Construct the SQL query to retrieve the cat_id for the provided user ID
    const userQuery = `SELECT cat_id FROM users WHERE id = '${userId}'`;

    // Execute the user query
    pool.query(userQuery, (error, userResults) => {
      if (error) {
        console.error('Error retrieving user cat_id:', error);
        reject('Internal server error');
      } else {
        if (userResults.length > 0) {
          const userCat = JSON.parse(userResults[0].cat_id);

          // Calculate the start and end dates for the current week
          const currentDate = new Date();
          const currentYear = currentDate.getFullYear();
          const currentMonth = currentDate.getMonth();
          const currentDateOfMonth = currentDate.getDate();
          const firstDayOfWeek = new Date(currentYear, currentMonth, currentDateOfMonth - currentDate.getDay());
          const lastDayOfWeek = new Date(currentYear, currentMonth, currentDateOfMonth + (6 - currentDate.getDay()));

          // Format the start and end dates as strings in the format 'YYYY-MM-DD'
          const startDate = firstDayOfWeek.toISOString().split('T')[0];
          const endDate = lastDayOfWeek.toISOString().split('T')[0];

          // Construct the SQL query with JOIN and date filter
          const query = `
            SELECT *
            FROM vacancies
            WHERE vacancies.category_id IN (${userCat.map(value => `'${value}'`).join(',')})
            AND created_at >= '${startDate}' AND created_at <= '${endDate}'
          `;

          // Execute the vacancies query
          pool.query(query, (error, results) => {
            if (error) {
              console.error('Error retrieving weekly vacancies:', error);
              reject('Internal server error');
            } else {
              resolve(results);
            }
          });
        } else {
          reject('User not found');
        }
      }
    });
  });
}

function fetchLatestVacancies(userId, startIndex) {
  return new Promise((resolve, reject) => {
    // Construct the SQL query to retrieve the cat_id for the provided user ID
    const userQuery = `SELECT cat_id FROM users WHERE id = '${userId}'`;

    // Execute the user query
    pool.query(userQuery, (error, userResults) => {
      if (error) {
        console.error('Error retrieving user cat_id:', error);
        reject('Internal server error');
      } else {
        if (userResults.length > 0) {
          const userCat = JSON.parse(userResults[0].cat_id);

          // Construct the SQL query with JOIN, startIndex, and limit
          const query = `
            SELECT *
            FROM vacancies
            WHERE vacancies.category_id IN (${userCat.map(value => `'${value}'`).join(',')})
            ORDER BY created_at DESC
            LIMIT 20 OFFSET ${startIndex}
          `;

          // Execute the vacancies query
          pool.query(query, (error, results) => {
            if (error) {
              console.error('Error retrieving latest vacancies:', error);
              reject('Internal server error');
            } else {
              resolve(results);
            }
          });
        } else {
          reject('User not found');
        }
      }
    });
  });
}


app.get("/vacancy/new", async (req, res) => {
  try {
    const userId = req.user.id;
    const selectedCategories = req.query.selectedCategories.split(",");

    const newVacancies = await getVacanciesByCategories(userId, selectedCategories);

    res.json(newVacancies);
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get("/vacancy/others", async (req, res) => {
  try {
    const userId = req.user.id;
    const selectedCategories = req.query.selectedCategories.split(",");

    const otherVacancies = await getVacanciesByCategories(userId, selectedCategories);

    res.json(otherVacancies);
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});




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
app.get("/vacancy/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM vacancies WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving companies");
    }

    return res.json(results);
  });
});
app.put('/vacancie/:id', async (req, res) => {
  const vacancyId = req.params.id;

  try {
    const query = 'UPDATE vacancies SET status = 0 WHERE id = ?';
    const result = pool.query(query, [vacancyId]);

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
app.post('/vacanci', cors(), async (req, res) => {
  try {
    const {
      user_id,
      company_id,
      city_id,
      category_id,
      job_type_id,
      experience_id,
      education_id,
      position,
      min_salary,
      max_salary,
      min_age,
      max_age,
      salary_type,
      requirement,
      description,
      contact_name,
      accept_type,
      contact_info,
      deadline,
    } = req.body;

    const slug = position.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    const query = `INSERT INTO vacancies (user_id, company_id, city_id, category_id, job_type_id, experience_id, education_id, position, slug, min_salary, max_salary, min_age, max_age, salary_type, requirement, description, contact_name, accept_type, contact_info, deadline, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;
    const values = [
      user_id,
      company_id,
      city_id,
      category_id,
      job_type_id,
      experience_id,
      education_id,
      position,
      slug,
      min_salary,
      max_salary,
      min_age,
      max_age,
      salary_type,
      requirement,
      description,
      contact_name,
      accept_type,
      contact_info,
      deadline,
    ];

    // Execute the database query
    await pool.query(query, values);
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
app.get("/candidates", async (req, res) => {
  try {
    pool.query("SELECT * FROM candidates ORDER BY created_at DESC", (error, results, fields) => {
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
app.post('/companiy', cors(), upload.single('image'), async (req, res) => {
  try {
    const {
      user_id,
      sector_id,
      average,
      name,
      about,
      address,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
    } = req.body;

    const imagePath = req.file ? req.file.path : null;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (imagePath) {
      // Upload the image to Azure Blob Storage
      const uploadedFileName = await uploadToBlobStorage(req.file);
      imageUrl = `back/assets/images/companies/${uploadedFileName}`;
    }

    const query = `INSERT INTO companies (user_id, sector_id, average, about, name, address, image, website, map, hr, instagram, linkedin, facebook, twitter, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;
    const values = [
      user_id,
      sector_id,
      average,
      about,
      name,
      address,
      imageUrl,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
      slug,
    ];

    // Execute the database query
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error adding company' });
      } else {
        res.status(201).json({ message: 'Company added successfully' });
      }
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Error uploading image' });
  }
});
app.put('/companie/:id', cors(), upload.single('image'), async (req, res) => {
  try {
    const companyId = req.params.id;
    const {
      user_id,
      sector_id,
      average,
      name,
      about,
      address,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
    } = req.body;

    const imagePath = req.file ? req.file.path : null;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (imagePath) {
      // Upload the image to Azure Blob Storage
      const uploadedFileName = await uploadToBlobStorage(req.file);
      imageUrl = `back/assets/images/trainings/${uploadedFileName}`;
    }

    const query = `UPDATE companies SET user_id = ?, sector_id = ?, average = ?, about = ?, name = ?, address = ?, image = ?, website = ?, map = ?, hr = ?, instagram = ?, linkedin = ?, facebook = ?, twitter = ?, slug = ?, updated_at = NOW() WHERE id = ?`;
    const values = [
      user_id,
      sector_id,
      average,
      about,
      name,
      address,
      imageUrl,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
      slug,
      companyId,
    ];

    // Execute the database query
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating company' });
      } else {
        res.status(200).json({ message: 'Company updated successfully' });
      }
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Error uploading image' });
  }
});

app.put('/compani/:id', cors(), upload.single('image'), async (req, res) => {
  try {
    const companyId = req.params.id;
    const {
      user_id,
      sector_id,
      average,
      name,
      about,
      address,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
    } = req.body;

    const imagePath = req.file ? req.file.path : null;
    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (imagePath) {
      // Upload the image to Azure Blob Storage
      const uploadedFileName = await uploadToBlobStorage(req.file);
      imageUrl = `back/assets/images/trainings/${uploadedFileName}`;
    }

    const query = `
      UPDATE companies 
      SET 
        user_id = ?, 
        sector_id = ?, 
        average = ?, 
        about = ?, 
        name = ?, 
        address = ?, 
        image = ?, 
        website = ?, 
        map = ?, 
        hr = ?, 
        instagram = ?, 
        linkedin = ?, 
        facebook = ?, 
        twitter = ?, 
        slug = ?, 
        status = 1, 
        updated_at = NOW() 
      WHERE 
        id = ?
    `;
    const values = [
      user_id,
      sector_id,
      average,
      about,
      name,
      address,
      imageUrl,
      website,
      map,
      hr,
      instagram,
      linkedin,
      facebook,
      twitter,
      slug,
      companyId,
    ];

    // Execute the database query
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating company' });
      } else {
        res.status(200).json({ message: 'Company updated successfully' });
      }
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ message: 'Error uploading image' });
  }
});

app.get("/cvs/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM cv WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving companies");
    }

    return res.json(results);
  });
});

app.get("/company/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM companies WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving companies");
    }

    return res.json(results);
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
app.post('/training', cors(),upload.single('image'), async (req, res) => {
  const { user_id, company_id, title, about, price, redirect_link, deadline } = req.body;
  const imagePath = req.file ? req.file.path : null;
  const slug = title.toLowerCase().replace(/\s+/g, '-');
  req.body.slug = slug; // Update the slug in the request body

  try {
    let imageUrl = null;

    // Check if file was uploaded
    if (imagePath) {
      // Upload the image to Azure Blob Storage
      const uploadedFileName = await uploadToBlobStorage(req.file);
      imageUrl = `back/assets/images/trainings/${uploadedFileName}`;
    }

    const query = `INSERT INTO trainings (user_id, company_id, title, slug, about, price, redirect_link, image, deadline, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;
    const values = [user_id, company_id, title, slug, about, price, redirect_link, imageUrl, deadline];

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
app.get("/cv/:userId", (req, res) => {
  const userId = req.params.userId;

  const sql = "SELECT * FROM cv WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving trainings");
    }

    return res.json(results);
  });
});
app.post('/civi', upload.fields([{ name: 'cv', maxCount: 1 }, { name: 'image', maxCount: 1 }]), async (req, res) => {
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
    const cvFile = req.files ? req.files['cv'][0] : null;
    const imageFile = req.files ? req.files['image'][0] : null;


    // Upload files to storage service (implement uploadToBlobStorage function accordingly)
    const cvUrl = cvFile ? await uploadToBlobStorage(cvFile, 'cv') : null;
    const imageUrl = imageFile ? await uploadToBlobStorage(imageFile, 'image') : null;

    // Additional logic for portfolios
    const portfolio = [];
    const numberOfPortfolios = Object.keys(req.body).reduce((count, key) => {
      if (key.startsWith('portfolio_job_name_')) {
        const index = parseInt(key.split('_')[3], 10); // Extract the index from the field name
        return Math.max(count, index + 1); // Get the maximum index
      }
      return count;
    }, 0);

    for (let i = 0; i < numberOfPortfolios; i++) {
      const jobName = req.body[`portfolio_job_name_${i}`];
      const company = req.body[`portfolio_company_${i}`];
      const link = req.body[`portfolio_link_${i}`];

      if (jobName && company && link) {
        const portfolioObj = {
          job_name: jobName,
          company: company,
          link: link,
        };

        portfolio.push(portfolioObj);
      }
    }

    const serializedPortfolio = JSON.stringify({ portfolio });

    // Generate slug
    const slug = `${name.toLowerCase()}-${surname.toLowerCase()}`.replace(/\s+/g, '-');

    // Perform database insertion (adjust your database query and connection accordingly)
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
      serializedPortfolio,
      slug,
    ];

    // Execute the query (replace with your database execution logic)
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error adding CV' });
      } else {
        // Send email to user
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: 'humbeteliyevaseide2001@gmail.com',
            pass: 'nwudhimwttuqdzxv',
          },
        });

        const mailOptions = {
          from: req.body.email,
          to: 'humbesaida@gmail.com',
          subject: 'CV Added Successfully',
          text: 'Your CV has been added successfully. Thank you!',
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error sending email:', error);
          } else {
            console.log('Email sent:', info.response);
          }
        });

        res.status(201).json({ message: 'CV added successfully', imageUrl });
      }
    });
  } catch (error) {
    console.error('Error uploading CV:', error);
    res.status(500).json({ message: 'Error uploading CV' });
  }
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

  const portfolio = [];
  const numberOfPortfolios = 2; // Define the total number of portfolios dynamically

  // Assuming you have form fields with names like 'portfolio_job_name_1', 'portfolio_company_1', 'portfolio_link_1', and so on
  for (let i = 1; i <= numberOfPortfolios; i++) {
    const jobName = req.body[`portfolio_job_name_${i}`];
    const company = req.body[`portfolio_company_${i}`];
    const link = req.body[`portfolio_link_${i}`];

    // Check if the portfolio object has valid data
    if (jobName && company && link) {
      const portfolioObj = {
        job_name: jobName,
        company,
        link,
      };
      portfolio.push(portfolioObj);
    }
  }

  try {
    const cvFile = req.files['cv'][0];
    const imageFile = req.files['image'][0];

    const cvUrl = await uploadToBlobStorage(cvFile, 'cv');
    const imageUrl = await uploadToBlobStorage(imageFile, 'cv');

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
      id,
    ];

    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating CV' });
      } else {
        // Send email to user
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
            user: 'humbeteliyevaseide2001@gmail.com',
            pass: 'nwudhimwttuqdzxv'
          }
        });

        const mailOptions = {
          from: req.body.email,
          to: 'humbesaida@gmail.com',
          subject: 'CV Updated Successfully',
          text: 'Your CV has been updated successfully. Thank you!',
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error sending email:', error);
          } else {
            console.log('Email sent:', info.response);
          }
        });

        res.status(200).json({ message: 'CV updated successfully', imageUrl });
      }
    });
  } catch (error) {
    console.error('Error uploading CV:', error);
    res.status(500).json({ message: 'Error uploading CV' });
  }
});

app.post("/reviews", async (req, res) => {
  try {
    const { user_id, company_id, message, rating } = req.body;

    const getUserQuery = "SELECT name AS fullname FROM users WHERE id = ?";
    pool.query(getUserQuery, [user_id], (error, results, fields) => {
      if (error) throw error;

      // Check if user exists and retrieve the full name
      if (results.length === 0) {
        throw new Error("User not found");
      }
      const fullname = results[0].fullname;

      if (!rating) {
        throw new Error("Rating is required");
      }

      pool.query(
        "INSERT INTO review (user_id, fullname, company_id, message, rating, created_at, updated_at) VALUES (?, ?, ?, ?, ?, NOW(), NOW())",
        [user_id, fullname, company_id, message, rating],
        (error, results, fields) => {
          if (error) throw error;
          console.log("Review added");
          res.sendStatus(201);
        }
      );
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/review-users/:companyId", async (req, res) => {
  try {
    const { companyId } = req.params;
    const getUserCountQuery = "SELECT COUNT(user_id) AS user_count FROM review WHERE company_id = ?";
    
    pool.query(getUserCountQuery, [companyId], (error, results, fields) => {
      if (error) throw error;
      const userCount = results[0].user_count;

      res.json({ userCount });
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/ratings/:company_id", async (req, res) => {
  try {
    const { company_id } = req.params;

    const getRatingsQuery = "SELECT COUNT(*) AS total_ratings FROM review WHERE status = '1'";
    pool.query(getRatingsQuery, (error, results, fields) => {
      if (error) throw error;
      const totalRatings = results[0].total_ratings;

      const getCompanyRatingsQuery = "SELECT COUNT(*) AS company_ratings FROM review WHERE company_id = ? AND rating IS NOT NULL AND status = '1'";
      pool.query(getCompanyRatingsQuery, [company_id], (error, results, fields) => {
        if (error) throw error;
        const companyRatings = results[0].company_ratings;

        console.log("Total Ratings:", totalRatings);
        console.log("Company Ratings:", companyRatings);

        const percentage = ((companyRatings / totalRatings) * 100).toFixed(0);
        console.log("Percentage:", percentage);
        res.json({ percentage });
      });
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/ratings", async (req, res) => {
  try {
    pool.query("SELECT * FROM review WHERE status = '1' ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/reviews/:companyId", async (req, res) => {
  try {
    const { companyId } = req.params;
    pool.query(
      "SELECT review.*, users.image, users.name FROM review INNER JOIN users ON review.user_id = users.id WHERE review.company_id = ?",
      [companyId],
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

app.get("/average-rating/:company_id", async (req, res) => {
  try {
    const { company_id } = req.params;

    const getAverageRatingQuery = "SELECT AVG(rating) AS average_rating FROM review WHERE company_id = ? AND rating IS NOT NULL AND status = '1'";
    pool.query(getAverageRatingQuery, [company_id], (error, results, fields) => {
      if (error) throw error;
      const averageRating = results[0].average_rating;

      console.log("Average Rating:", averageRating);

      res.json({ averageRating });
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});
app.get("/rating/:company_id", async (req, res) => {
  try {
    const { company_id } = req.params;

    const getRatingsQuery = "SELECT COUNT(*) AS count, rating FROM review WHERE company_id = ? AND rating IS NOT NULL AND status = '1' GROUP BY rating";
    pool.query(getRatingsQuery, [company_id], (error, results, fields) => {
      if (error) throw error;

      // Format the ratings data
      const ratingsData = results.map((result) => ({
        rating: result.rating,
        count: result.count,
      }));

      console.log("Ratings Data:", ratingsData);
      res.json(ratingsData);
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


// Function to upload image to Azure Blob Storage
// const uploadToBlobStorage = async (file) => {
//   const fileName = 'trainings/' + Date.now() + '_' + file.originalname; // Include 'trainings/' as part of the blob name
//   const blockBlobClient = containerClient.getBlockBlobClient(fileName);
//   await blockBlobClient.uploadFile(file.path);
//   return fileName;
// };
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

  const sql = `SELECT * FROM vacancies WHERE id IN (SELECT vacancy_id FROM favorits WHERE user_id = ?)`;

  pool.query(sql, [userId], (error, results) => {
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
app.post('/apply', (req, res) => {
  const { userId, vacancyId, cvId } = req.body;

  const selectQuery = 'SELECT name, email, surname, contact_phone, cv FROM cv WHERE user_id = ? AND id = ?';

  pool.query(selectQuery, [userId, cvId], (selectError, selectResults) => {
    if (selectError) {
      console.error('Error retrieving user information from cv:', selectError);
      res.status(500).json({ message: 'Error applying for the vacancy' });
      return;
    }

    if (selectResults.length === 0) {
      console.error('CV not found for the given user ID and CV ID');
      res.status(400).json({ message: 'CV not found' });
      return;
    }

    const user = selectResults[0];

    const insertQuery = 'INSERT INTO candidates (user_id, vacancy_id, name, mail, surname, phone, cv) VALUES (?, ?, ?, ?, ?, ?, ?)';
    const values = [userId, vacancyId, user.name, user.email, user.surname, user.contact_phone, user.cv];

    pool.query(insertQuery, values, (insertError, insertResults) => {
      if (insertError) {
        console.error('Error inserting application:', insertError);
        res.status(500).json({ message: 'Error applying for the vacancy' });
      } else {
        res.status(200).json({ message: 'Application submitted successfully' });
      }
    });
  });
});
app.post('/candidates', cors(), async (req, res) => {
  try {
  const cvFile = req.file;// Use req.file instead of req.files['cv'][0]
    const { vacancyId, name, email, surname, phone } = req.body;

    // Rest of your code here...

    const insertQuery = 'INSERT INTO candidates (vacancy_id, name, mail, surname, phone, cv) VALUES (?, ?, ?, ?, ?, ?)';
    const values = [vacancyId, name, email, surname, phone, cvFile];

    pool.query(insertQuery, values, (insertError, insertResults) => {
      if (insertError) {
        console.error('Error inserting application:', insertError);
        res.status(500).json({ message: 'Error applying for the vacancy' });
      } else {
        res.status(200).json({ message: 'Application submitted successfully' });
      }
    });
  } catch (error) {
    console.error('Error applying for the vacancy:', error);
    res.status(500).json({ message: 'Error applying for the vacancy' });
  }
});

app.get('/candidates/:user_id', (req, res) => {
  const userId = req.params.user_id;

  const selectQuery = 'SELECT * FROM candidates WHERE user_id = ?';
  pool.query(selectQuery, [userId], (selectError, selectResults) => {
    if (selectError) {
      console.error('Error retrieving candidates:', selectError);
      res.status(500).json({ message: 'Error retrieving candidates' });
    } else {
      res.status(200).json(selectResults);
    }
  });
});

app.listen(8000, () => {
  console.log(`Server is running on port 8000`);
});
