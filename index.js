import express from "express";
import { createConnection } from "mysql";

import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import session from "express-session";
import bodyParser from "body-parser";
import passport from "passport";
import mysql from "mysql";

const app = express();

const pool = mysql.createPool({
    connectionLimit: 10,
    host: '145.14.156.192',
    user: 'u983993164_1is',
    password: 'Buta2023@',
    database: 'u983993164_1is',
    timeout: 100000
  });
  
  pool.getConnection((err, connection) => {
    if (err) {
      console.error('Error connecting to database: ' + err.stack);
      return;
    }
  
    console.log('Connected to database with ID ' + connection.threadId);
  
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


app.get("/vacancies", async (req, res) => {
  try {
    pool.query("SELECT * FROM vacancies", (error, results, fields) => {
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
    pool.query("SELECT * FROM companies", (error, results, fields) => {
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

app.get("/cv", async (req, res) => {
  try {
    pool.query("SELECT * FROM cv", (error, results, fields) => {
      if (error) throw error;
      res.json(results);
    });
  } catch (error) {
    console.log(error);
    res.sendStatus(500);
  }
});

app.use("/cv/:id", async (req, res) => {
  try {
    const { id } = req.params;

    pool.query(
      "SELECT * FROM cv WHERE id = ?",
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
    pool.query("SELECT * FROM trainings", (error, results, fields) => {
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

app.post("/trainings", async (req, res) => {
    try {
      const { user_id, company_id, title, slug, about, redirect_link, image, price, payment_type, deadline  } = req.body;
      pool.query(
        "INSERT INTO trainings ( user_id, company_id, title, slug, about, redirect_link, image, price, payment_type, deadline,created_at, updated_at)  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW()) ",
        [ user_id, company_id, title, slug, about, redirect_link, image, price, payment_type, deadline],
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
    pool.query("SELECT * FROM blogs", (error, results, fields) => {
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
    const { user_id, vacancy_id } = req.body;
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

app.listen(3000, () => {
  console.log("Server listening on port 3000");
});

export default app;
