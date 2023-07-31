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
import FTP from 'ftp';
import fs from 'fs';
import cors from "cors";
import nodemailer from "nodemailer";
import schedule from 'node-schedule';
import { body, validationResult, param  } from 'express-validator';
const app = express();

const pool = mysql.createPool({
  connectionLimit: 10,
  host: "145.14.156.192",
  user: "u983993164_1is_test",
  password: "@Ucvlqcq8$",
  database: "u983993164_1is_test",
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


const storage = multer.memoryStorage();
const upload = multer({ storage });

// FTP'ye dosya yükleme
async function uploadFileToFtp(fileContents, remotePath) {
  return new Promise((resolve, reject) => {
    const client = new FTP();

    client.on('ready', () => {
      console.log('FTP bağlantısı başarılı. Dosya yükleniyor...');

      client.put(fileContents, remotePath, (error) => {
        client.end(); // Close the FTP connection

        if (error) {
          console.error('Dosya yükleme hatası:', error);
          reject(error);
        } else {
          console.log('Dosya başarıyla yüklendi!');
          resolve();
        }
      });
    });

    client.on('error', (error) => {
      console.error('FTP bağlantı hatası:', error);
      reject(error);
    });

    client.connect({
      host: '145.14.156.206', // FTP sunucu adresi
      user: 'u983993164', // FTP kullanıcı adı
      password: 'Pa$$w0rd!', // FTP şifre
      port: 21, // FTP portu
    });
  });
}

// Hosting sunucusuna dosya kaydetme
async function saveFileToHosting(fileContents, fileName, folderName) {
  return new Promise((resolve, reject) => {
    const localDirectory = `back/assets/images/${folderName}`;
    const localPath = `${localDirectory}/${fileName}`; // Kaydedilecek yerel dosya yolunu belirtin

    // Create directory if it doesn't exist
    if (!fs.existsSync(localDirectory)) {
      fs.mkdirSync(localDirectory, { recursive: true });
    }

    fs.writeFile(localPath, fileContents, (error) => {
      if (error) {
        console.error('Dosya kaydetme hatası:', error);
        reject(error);
      } else {
        console.log('Dosya hosting sunucusuna kaydedildi!');
        const remotePath = `/domains/butagrup.az/public_html/1is/public/back/assets/images/${folderName}/${fileName}`; // Yüklenecek dosyanın uzak FTP yolu
        uploadFileToFtp(fileContents, remotePath)
          .then(() => {
            console.log('Dosya FTP sunucusuna yüklendi!');
            resolve();
          })
          .catch((error) => {
            console.error('FTP dosya yükleme hatası:', error);
            reject(error);
          });
      }
    });
  });
}

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
          return res.json({ id: user.id, token }); // Return user ID and token in the response
        });
      }
    );
  }
);
const DEFAULT_USER_IMAGE = 'back/assets/images/users/default-user.png';

app.post('/google-signin', (req, res) => {
  const { email, givenName, familyName, photo } = req.body;

  // Perform validation
  const isValid = (email && givenName);
  if (!isValid) {
    return res.status(400).json({ message: 'Invalid login. Please provide email and givenName' });
  }

  const insertQuery = 'INSERT INTO users (email, name, image, surname) VALUES (?, ?, ?, ?)';
  const values = [email, givenName, photo || DEFAULT_USER_IMAGE, familyName || generateRandomText(givenName)];

  pool.query(insertQuery, values, (err, results) => {
    if (err) {
      console.log(err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    return res.status(200).json({ message: 'User information stored successfully' });
  });
});

function generateRandomText(name) {
  // Extract the starting alphabet of the givenName
  const firstLetter = name.charAt(0);
  return firstLetter;
}




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




app.delete("/fv/:cvId", async (req, res) => {
  try {
    const cvId = req.params.vacancyId;
    const query = "DELETE FROM favorits WHERE cv_id = ?";
    pool.query(query, [cvId], (error, results, fields) => {
      if (error) {
        console.error(error);
        res.sendStatus(500);
      } else {
        console.log(`Removed from favorites`);
        res.sendStatus(200);
      }
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
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
function generateVerificationCode() {
  const length = 6; // Length of the verification code
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'; // Characters to choose from
  let code = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    code += characters.charAt(randomIndex);
  }

  return code;
}

    
 app.post(
  '/forgot-password',
  [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email'),
  ],
  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    // Check if email exists in the database
    pool.query('SELECT * FROM users WHERE email = ?', [email], (error, results) => {
      if (error) {
        console.error('Error executing database query:', error);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const user = results[0];

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      // Generate verification code
      const verificationCode = generateVerificationCode();

      // Update the user's verification code in the database
      pool.query('UPDATE users SET email_verification_code = ? WHERE id = ?', [verificationCode, user.id], (error) => {
        if (error) {
          console.error('Error executing database query:', error);
          return res.status(500).json({ error: 'Internal server error' });
        }

        // Send verification code via email
      let transport = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'humbeteliyevaseide2001@gmail.com',
        pass: 'nwudhimwttuqdzxv'
      }
    });
      // Send the reset token to the user's email


        const mailOptions = {
          from: 'humbeteliyevaseide2001@gmail.com',
          to: email,
          subject: 'Password Reset',
          text: `Your verification code is: ${verificationCode}`,
        };

        transport.sendMail(mailOptions, (error) => {
          if (error) {
            console.error('Error sending email:', error);
            return res.status(500).json({ error: 'Error sending email' });
          }
          return res.status(200).json({ message: 'Verification code sent' });
        });
      });
    });
  }
);


app.get("/fvrts/:userId", (req, res) => {
  const { userId } = req.params;

  const sql = `SELECT * FROM cv WHERE id IN (SELECT cv_id FROM favorits WHERE user_id = ?)`;

  pool.query(sql, [userId], (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving favorites");
    }

    return res.json(results);
  });
});
// Example API endpoint for handling "Reset Password" request
app.post(
  '/reset-password',
  [
    body('code').isLength({ min: 6 }).withMessage('Verification code must be at least 6 characters'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ],
  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { code, password } = req.body;

    // Find the user based on the verification code in the database
    pool.query('SELECT * FROM users WHERE email_verification_code = ?', [code], (error, results) => {
      if (error) {
        console.error('Error executing database query:', error);
        return res.status(500).json({ error: 'Internal server error' });
      }

      const user = results[0];

      if (!user) {
        return res.status(404).json({ error: 'User not found or invalid verification code' });
      }

      // Check if verification code is valid (no expiration check)

      // Hash the new password
      bcrypt.hash(password, 10, (hashError, hashedPassword) => {
        if (hashError) {
          console.error('Error hashing password:', hashError);
          return res.status(500).json({ error: 'Internal server error' });
        }

        // Update the user's password in the database with the hashed password
        pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (updateError) => {
          if (updateError) {
            console.error('Error executing database query:', updateError);
            return res.status(500).json({ error: 'Internal server error' });
          }

          // Clear the verification code from the user object
          pool.query('UPDATE users SET email_verification_code = null WHERE id = ?', [user.id], (clearError) => {
            if (clearError) {
              console.error('Error executing database query:', clearError);
              return res.status(500).json({ error: 'Internal server error' });
            }

            return res.status(200).json({ message: 'Password reset successful' });
          });
        });
      });
    });
  }
);

// Assuming you are using Express.js for your backend

app.delete("/fav/:vacancyId", async (req, res) => {
  try {
    const vacancyId = req.params.vacancyId;
    const query = "DELETE FROM favorits WHERE vacancy_id = ?";
    pool.query(query, [vacancyId], (error, results, fields) => {
      if (error) {
        console.error(error);
        res.sendStatus(500);
      } else {
        console.log(`Removed from favorites`);
        res.sendStatus(200);
      }
    });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
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
app.post('/candidate',cors(), upload.fields([{ name: 'cv', maxCount: 1 }]), async (req, res) => {
  const { vacancyId, name, email, surname, phone } = req.body;

  try {
    const cvFile = req.files ? req.files['cv'][0] : null;


    // Upload files to storage service (implement uploadToBlobStorage function accordingly)
    let cvUrl = null;

    
    if (cvFile) {
      // Validate the CV file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = cvFile.buffer;
      const extension = '.pdf'; // Assuming CV files are in PDF format

      const fileName = `cv_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('CV dosyası yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'cvs');
      console.log('CV dosyası yükleme tamamlandı!');

      cvUrl = `back/assets/images/cvs/${fileName}`;
    }

      const query =
      'INSERT INTO candidates (vacancy_id, name, surname,  mail, phone,  cv, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?,  NOW(), NOW())';

    const values = [
      vacancyId,
      name,
      surname,
      email,
      phone,
      cvUrl,
     
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
          subject: 'Candidate Added Successfully',
          text: 'Your request has been added successfully. Thank you!',
        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error sending email:', error);
          } else {
            console.log('Email sent:', info.response);
          }
        });

        res.status(201).json({ message: 'Candidate added successfully' });
      }
    });
  } catch (error) {
    console.error('Error uploading Candidate:', error);
    res.status(500).json({ message: 'Error uploading Candidate' });
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
const executeQuery = (query, params) => {
  return new Promise((resolve, reject) => {
    pool.query(query, params, (error, results) => {
      if (error) {
        reject(error);
      } else {
        resolve(results);
      }
    });
  });
};

app.post('/change-password', async (req, res) => {
  const { email, oldPassword, newPassword } = req.body;

  try {
    const getUserQuery = `SELECT * FROM users WHERE email = ?`;
    const userResults = await executeQuery(getUserQuery, [email]);

    if (userResults.length === 0) {
      res.status(401).send('User not found');
      return;
    }

    const user = userResults[0];
    const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);

    if (!isOldPasswordCorrect) {
      res.status(401).send('Incorrect old password');
      return;
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const updatePasswordQuery = `UPDATE users SET password = ? WHERE email = ?`;
    await executeQuery(updatePasswordQuery, [hashedNewPassword, email]);

    res.status(200).send('Password updated successfully');
  } catch (error) {
    console.error(error);
    res.status(500).send('Error updating password');
  }
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

app.route('/vacancy')
  .get(cors(), (req, res) => {
    const userId = req.query.userId;
    const startIndex = req.query.startIndex || 0; // Default startIndex to 0 if not provided

    if (!userId) {
      return res.status(400).json({ error: 'userId is required in the query parameters' });
    }

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

// Assuming you have set up a database connection pool named 'pool'
app.get("/favorited_vacancies/:user_id/:vacancy_id", async (req, res) => {
  const user_id = req.params.user_id;
  const vacancy_id = req.params.vacancy_id;
  
  try {
    pool.query(
      "SELECT * FROM favorits WHERE user_id = ? AND vacancy_id = ?",
      [user_id, vacancy_id],
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
    pool.query("SELECT * FROM vacancies WHERE status = '1' ORDER BY created_at DESC", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.get('/vacancy/:userId', [
  param('userId').isNumeric().withMessage('Invalid userId'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const userId = req.params.userId;

  const sql = "SELECT * FROM cv WHERE user_id = ? AND status = '1'"; 
  const values = [userId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving cv");
    }

    return res.json(results);
  });
});

app.get('/vacancy/:userId', [
  param('userId').isNumeric().withMessage('Invalid userId'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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
const vacancyValidationRules = [
  body('user_id').notEmpty().isInt(),
  body('company_id').notEmpty().isInt(),
  body('city_id').notEmpty().isInt(),
  body('category_id').notEmpty().isInt(),
  body('job_type_id').notEmpty().isInt(),
  body('experience_id').notEmpty().isInt(),
  body('education_id').notEmpty().isInt(),
  body('position').notEmpty().isString(),
  body('min_salary').notEmpty().isInt(),
  body('max_salary').notEmpty().isInt(),
  body('min_age').notEmpty().isInt(),
  body('max_age').notEmpty().isInt(),
  body('requirement').notEmpty().isString(),
  body('description').notEmpty().isString(),
  body('contact_name').notEmpty().isString(),
  body('accept_type').notEmpty().isString(),
  body('contact_info').notEmpty().isString(),
  body('deadline').notEmpty().isString(),
];
app.post('/vacanc', cors(), async (req, res) => {
  const {
    user_id,
    selected_company_id,
    category_id,
    city_id,
    job_type_id,
    experience_id,
    education_id,
    position,
    min_salary,
    max_salary,
    min_age,
    salary_type,
    max_age,
    requirement,
    description,
    contact_name,
    accept_type,
    deadline
  } = req.body;

  try {
    // Retrieve all company_ids associated with the logged-in user's user_id
    const getCompanyIdsQuery = 'SELECT id FROM companies WHERE user_id = ?';
    const companyIdsValues = [user_id];

    // Execute the query to get all company_ids (replace with your database execution logic)
    pool.query(getCompanyIdsQuery, companyIdsValues, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error getting company_ids' });
      } else {
        if (results.length === 0) {
          res.status(400).json({ message: 'Companies not found for the logged-in user' });
          return;
        }

        // Extract all company_ids associated with the logged-in user
        const company_ids = results.map(result => result.id);

        // Check if the selected_company_id belongs to the logged-in user
        if (!company_ids.includes(selected_company_id)) {
          res.status(400).json({ message: 'Selected company not found or not owned by the logged-in user' });
          return;
        }

        // Generate slug
        const slug = `${position.toLowerCase()}`.replace(/\s+/g, '-');

        // Perform database insertion (adjust your database query and connection accordingly)
        const insertVacancyQuery =
          'INSERT INTO vacancies (user_id, company_id, category_id, city_id, education_id, experience_id, job_type_id, min_salary,salary_type, max_salary, min_age, max_age, requirement,  position, description, contact_name, accept_type, deadline, slug, created_at, updated_at) VALUES (?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())';

        // Adjust min_salary and max_salary values based on salary_type
        let insertVacancyValues;
        if (salary_type === 1) {
          insertVacancyValues = [
            user_id,
            selected_company_id,
            category_id,
            city_id,
            education_id,
            experience_id,
            job_type_id,
            min_salary,
            salary_type.toString(),
            max_salary,
            min_age,
            max_age,
            requirement,
            position,
            description,
            contact_name,
            accept_type,
            deadline,
            slug,
          ];
        } else if (salary_type === 0) {
          // When salary_type is 0, set min_salary and max_salary to null
          insertVacancyValues = [
            user_id,
            selected_company_id,
            category_id,
            city_id,
            education_id,
            experience_id,
            job_type_id,
            null,
            salary_type.toString(),
            null,
            min_age,
            max_age,
            requirement,
            position,
            description,
            contact_name,
            accept_type,
            deadline,
            slug,
          ];
        } else {
          res.status(400).json({ message: 'Invalid salary_type' });
          return;
        }

        // Execute the query to insert the vacancy (replace with your database execution logic)
        pool.query(insertVacancyQuery, insertVacancyValues, (error, results) => {
          if (error) {
            console.error(error);
            res.status(500).json({ message: 'Error adding Vacancy' });
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
              subject: 'Vacancy Added Successfully',
              text: 'Your Vacancy has been added successfully. Thank you!',
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('Error sending email:', error);
              } else {
                console.log('Email sent:', info.response);
              }
            });

            res.status(201).json({ message: 'Vacancy added successfully' });
          }
        });
      }
    });
  } catch (error) {
    console.error('Error uploading Vacancy:', error);
    res.status(500).json({ message: 'Error uploading Vacancy' });
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
const companyValidationRules = [
  body('user_id').notEmpty().isInt(),
  body('sector_id').notEmpty().isInt(),
  body('average').notEmpty().isFloat(),
  body('name').notEmpty().isString(),
  body('about').notEmpty().isString(),
  body('address').notEmpty().isString(),
  body('website').optional().isURL(),
  body('map').optional().isString(),
  body('hr').optional().isString(),
  body('instagram').optional().isString(),
  body('linkedin').optional().isString(),
  body('facebook').optional().isString(),
  body('twitter').optional().isString(),
];

app.post('/companiy',cors(), upload.single('image'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

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

    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (req.file) {
      const fileContents = req.file.buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `company_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'companies');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/companies/${fileName}`;
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

    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (req.file) {
      const fileContents = req.file.buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `company_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'companies');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/companies/${fileName}`;
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

app.put('/training/:id', cors(), upload.single('image'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const trainingId = req.params.id;
    const { user_id, company_id, title, about, payment_type, redirect_link, deadline } = req.body;

    const slug = title.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug; // Update the slug in the request body

    let price = null;

    // Check if payment_type is 1 (pay)
    if (payment_type === '1') {
      price = req.body.price; // Set price if it is pay
    }

    let imageUrl = null;

    // Check if file was uploaded
    if (req.file) {
      // Validate the image file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = req.file.buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `training_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'trainings');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/trainings/${fileName}`;
    }

    const query = `
      UPDATE trainings
      SET user_id = ?, company_id = ?, title = ?, slug = ?, about = ?, payment_type = ?, price = ?, redirect_link = ?, image = ?, deadline = ?, updated_at = NOW()
      WHERE id = ?
    `;
    const values = [user_id, company_id, title, slug, about, payment_type, price, redirect_link, imageUrl, deadline, trainingId];

    // Execute the database query
    pool.query(query, values, (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ message: 'Error updating training' });
      } else {
        res.status(200).json({ message: 'Training updated successfully' });
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

    const slug = name.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug;

    let imageUrl = null;

    // Check if file was uploaded
    if (req.file) {
      const fileContents = req.file.buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `company_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'companies');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/companies/${fileName}`;
    } else {
      // If no new image is uploaded, retain the existing image URL
      const query = 'SELECT image FROM companies WHERE id = ?';
      const existingImageResult = await pool.query(query, [companyId]);

      if (existingImageResult && existingImageResult.length > 0) {
        imageUrl = existingImageResult[0].image;
      }
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


app.get("/cv/:cvId", (req, res) => {
  const cvId = req.params.cvId;

  const sql = "SELECT * FROM cv WHERE id = ? AND status = '1'"; 
  const values = [cvId];

  pool.query(sql, values, (error, results) => {
    if (error) {
      console.error(error);
      return res.status(500).send("Error retrieving CV");
    }

    if (results.length === 0) {
      return res.status(404).send("CV not found");
    }

    return res.json(results[0]);
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
const trainingValidationRules = [
  body('user_id').notEmpty().isInt(),
  body('company_id').notEmpty().isInt(),
  body('title').notEmpty().isString(),
  body('about').notEmpty().isString(),
  body('price').notEmpty().isFloat(),
  body('redirect_link').optional().isURL(),
  body('deadline').notEmpty().isString(),
];

app.post('/training', cors(), upload.single('image'), async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { user_id, company_id, title, about, payment_type, redirect_link, deadline } = req.body;

    const slug = title.toLowerCase().replace(/\s+/g, '-');
    req.body.slug = slug; // Update the slug in the request body

    let price = null;

    // Check if payment_type is 1 (pay)
    if (payment_type === '1') {
      price = req.body.price; // Set price if it is pay
    }

    let imageUrl = null;

    // Check if file was uploaded
    if (req.file) {
      // Validate the image file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = req.file.buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `training_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'trainings');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/trainings/${fileName}`;
    }

    const query = `INSERT INTO trainings (user_id, company_id, title, slug, about, payment_type, price, redirect_link, image, deadline, created_at, updated_at) VALUES (?,?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())`;
    const values = [user_id, company_id, title, slug, about, payment_type, price, redirect_link, imageUrl, deadline];

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
app.get("/civ/:userId", (req, res) => {
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
app.post('/civi',cors(), upload.fields([{ name: 'cv', maxCount: 1 }, { name: 'image', maxCount: 1 }]), async (req, res) => {
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
    portfolio
  } = req.body;

  try {
    const cvFile = req.files ? req.files['cv'][0] : null;
    const imageFile = req.files ? req.files['image'][0] : null;

    // Upload files to storage service (implement uploadToBlobStorage function accordingly)
    let cvUrl = null;
    let imageUrl = null;
    
    if (cvFile) {
      // Validate the CV file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = cvFile.buffer;
      const extension = '.pdf'; // Assuming CV files are in PDF format

      const fileName = `cv_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('CV dosyası yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'cvs');
      console.log('CV dosyası yükleme tamamlandı!');

      cvUrl = `back/assets/images/cvs/${fileName}`;
    }
    // Check if file was uploaded
    if (imageFile) {
      // Validate the image file (e.g., check file size, type)
      // Your validation logic here
    
      const fileContents = req.files['image'][0].buffer;
      const extension = '.png'; // Change the extension based on your file type validation
    
      const fileName = `cv_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name
    
      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'cv_photo');
      console.log('Dosya yükleme tamamlandı!');
    
      imageUrl = `back/assets/images/cv_photo/${fileName}`;
    }

    // Additional logic for portfolios
   const portfolioData = JSON.parse(portfolio);
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
      JSON.stringify(portfolioData), // Convert portfolioData back to JSON string
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






app.put('/civi/:id', upload.fields([{ name: 'cv', maxCount: 1 }, { name: 'image', maxCount: 1 }]), async (req, res) => {
  const { id } = req.params;

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
    portfolio
  } = req.body;

  try {
    const cvFile = req.files ? req.files['cv'][0] : null;
    const imageFile = req.files ? req.files['image'][0] : null;

    // Upload files to storage service (implement uploadToBlobStorage function accordingly)
    let cvUrl = null;
    let imageUrl = null;

    if (cvFile) {
      // Validate the CV file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = cvFile.buffer;
      const extension = '.pdf'; // Assuming CV files are in PDF format

      const fileName = `cv_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('CV dosyası yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'cvs');
      console.log('CV dosyası yükleme tamamlandı!');

      cvUrl = `back/assets/images/cvs/${fileName}`;
    }
    // Check if file was uploaded
    if (imageFile) {
      // Validate the image file (e.g., check file size, type)
      // Your validation logic here

      const fileContents = req.files['image'][0].buffer;
      const extension = '.png'; // Change the extension based on your file type validation

      const fileName = `cv_${uuidv4().substring(0, 6)}${extension}`; // Generate a random file name

      console.log('Dosya yüklemesi başlıyor...');
      await saveFileToHosting(fileContents, fileName, 'cv_photo');
      console.log('Dosya yükleme tamamlandı!');

      imageUrl = `back/assets/images/cv_photo/${fileName}`;
    }

    // Additional logic for portfolios
  const portfolioData = JSON.parse(portfolio);

    // Generate slug
    const slug = `${name.toLowerCase()}-${surname.toLowerCase()}`.replace(/\s+/g, '-');

    // Perform database update (adjust your database query and connection accordingly)
    const query =
      'UPDATE cv SET user_id = ?, category_id = ?, city_id = ?, education_id = ?, experience_id = ?, job_type_id = ?, gender_id = ?, name = ?, surname = ?, father_name = ?, email = ?, contact_phone = ?, position = ?, about_education = ?, salary = ?, birth_date = ?, work_history = ?, skills = ?, cv = ?, image = ?, portfolio = ?, slug = ?, updated_at = NOW() WHERE id = ?';

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
   JSON.stringify(portfolioData),
      slug,
      id,
    ];

    // Execute the query (replace with your database execution logic)
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
            pass: 'nwudhimwttuqdzxv',
          },
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


app.post("/fav", async (req, res) => {
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
