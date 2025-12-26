import express from "express";
import bodyParser from "body-parser";
import env from "dotenv";
import pg from "pg";
import { format } from "date-fns";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session, { Session } from "express-session";

env.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = parseInt(process.env.SALT_ROUNDS, 10);


app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // 1 day
      httpOnly: true,
      sameSite: "lax",
      secure: false, // set true only in HTTPS production
    },
  })
);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

const { Pool } = pg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect()
  .then(() => console.log("✅ Connected to Supabase via Pool!"))
  .catch((err) => console.error("❌ Connection error:", err));

async function getPosts() {
  const result = await db.query("SELECT * FROM posts");
  return result.rows;
}

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/home", async (req, res) => {
  if (req.isAuthenticated()) {
    const posts = await getPosts();
    res.render("home.ejs", { array: posts });
  } else {
    res.redirect("/register");
  }
});

app.get("/about", (req, res) => {
  res.render("about.ejs");
});

app.get("/write", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("write.ejs");
  } else {
    res.redirect("/register");
  }
});

app.get("/read/:id", async (req, res) => {
  const postId = parseInt(req.params.id);
  const allposts = await getPosts();
  const result = await db.query("SELECT * FROM posts WHERE id = $1", [postId]);
  const post = result.rows[0];
  const formattedDate = format(
    new Date(post.published_date),
    "yyyy/MM/dd"
  ).replaceAll("/", "-");
  res.render("read.ejs", {
    post: post,
    published_date: formattedDate,
  });
});

app.post("/submit", async (req, res) => {
  try {
    await db.query(
      "INSERT INTO posts (title, subtitle, text, author, published_date) VALUES ($1, $2, $3, $4, $5)",
      [
        req.body["title"],
        req.body["subtitle"],
        req.body["text"],
        req.body["author"],
        req.body["date"],
      ]
    );
    const posts = await getPosts();
    res.render("home.ejs", { array: posts });
  } catch (err) {
    console.log(err);
    const posts = await getPosts();
    res.render("home.ejs", { array: posts });
  }
});

app.get("/edit/:id", async (req, res) => {
  const postId = parseInt(req.params.id);
  const allposts = await getPosts();
  const result = await db.query("SELECT * FROM posts WHERE id = $1", [postId]);
  const post = result.rows[0];
  const formattedDate = format(
    new Date(post.published_date),
    "yyyy/MM/dd"
  ).replaceAll("/", "-");
  res.render("edit.ejs", { post, published_date: formattedDate });
});

app.post("/update/:id", async (req, res) => {
  const postID = parseInt(req.params.id);

  try {
    const existing = await db.query("SELECT * FROM posts WHERE id = $1", [
      postID,
    ]);
    if (existing.rows.length !== 0) {
      await db.query(
        "UPDATE posts SET title=$1, subtitle=$2, text=$3, author=$4, published_date=$5 WHERE id=$6",
        [
          req.body.title,
          req.body.subtitle,
          req.body.text,
          req.body.author,
          req.body.date,
          postID,
        ]
      );
      res.redirect("/home");
    }
  } catch (err) {
    console.log(err);
    res.redirect("/home");
  }
});

app.post("/delete/:id", async (req, res) => {
  const postId = parseInt(req.params.id);
  try {
    await db.query("DELETE FROM posts WHERE id = $1;", [postId]);
    res.redirect("/home");
  } catch (err) {
    console.log(err);
    res.redirect("/home");
  }
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/signIn", (req, res) => {
  res.render("login.ejs");
});

app.post(
  "/signIn",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/register",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword; // make sure your form has this field

  // 1️⃣ Check if passwords match
  if (password !== confirmPassword) {
    console.log("Passwords do not match!");
    return res.send(
      `<script>alert('Passwords do not match!'); window.location.href='/register';</script>`
    );
  }

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/signIn");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.log(err);
              return res.redirect("/signIn");
            }
            console.log("success");
            res.redirect("/home");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use(
  new Strategy(
    {
      usernameField: "email", // 👈 THIS IS REQUIRED
      passwordField: "password",
    },
    async function verify(email, password, cb) {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
          email,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); // just store the user id
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]); // fetch user from DB
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
