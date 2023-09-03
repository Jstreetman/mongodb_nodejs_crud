import express from "express";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import passport from "passport";
import session from "express-session";
import flash from "express-flash";
import connectFlash from "connect-flash";
import { Strategy as LocalStrategy } from "passport-local";

const app = express();
const port = 3000;

// Middleware
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));

// Session configuration
app.use(
  session({
    secret: "NodeAuthPro", // Change this to a strong secret key
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport and session middleware
app.use(passport.initialize());
app.use(passport.session());

// Use express-flash and connect-flash middleware
app.use(flash());
app.use(connectFlash());

// MongoDB Connection
mongoose.connect("mongodb://localhost:27017/nodeauth", {
  useNewUrlParser: true,
});

// Define the User Schema
const UserSchema = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
});

const BlogSchema = new mongoose.Schema({
  username: String,
  createblog: String,
});

const Blog = mongoose.model("Blog", BlogSchema);
const User = mongoose.model("User", UserSchema);

// Passport Configuration
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      // Find the user by their username
      const user = await User.findOne({ username: username });

      if (!user) {
        return done(null, false, { message: "Invalid username or password" });
      }

      // Compare the provided password with the stored hashed password
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: "Invalid username or password" });
      }

      // If the username and password are valid, return the user
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  })
);

// Serialize and deserialize user
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id)
    .then((user) => {
      done(null, user); // Pass the user object to done() on success
    })
    .catch((err) => {
      done(err, null); // Pass an error to done() on failure
    });
});

// Routes

// Middleware to ensure authentication for /blog route
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next(); // If the user is authenticated, proceed to the next middleware or route handler
  }
  // If not authenticated, redirect to the login page
  res.redirect("/login");
}

// Handle user registration
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if the user already exists in the database
    const existingUser = await User.findOne({ username: username });

    if (existingUser) {
      req.flash("error", "Username already exists"); // Use flash messages
      return res.redirect("/register");
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user with the hashed password
    const newUser = new User({
      username: username,
      password: hashedPassword,
    });

    // Save the new user to the database
    await newUser.save();

    req.flash("success", "User registered successfully"); // Flash success message
    res.redirect("/login");
  } catch (error) {
    // Handle errors (e.g., database connection issues)
    console.error("Error:", error);
    req.flash("error", "Error registering user"); // Flash error message
    res.redirect("/register");
  }
});

// Handle login
app.post(
  "/signin",
  passport.authenticate("local", {
    successRedirect: "/blog",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.error("Error:", err);
    }
    res.redirect("/login");
  });
});

app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs", { message: req.flash("error") }); // Pass flash message to the login view
});

app.get("/blog", ensureAuthenticated, async (req, res) => {
  try {
    const username = req.user.username;

    // Fetch all blog entries for the current user
    const userBlogs = await Blog.find({ username: username });

    // Render the blog.ejs view and pass the user's blog entries as a variable
    res.render("create.ejs", { username: username, userBlogs: userBlogs });
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error fetching user's blogs"); // Flash error message
    res.redirect("/blog"); // Redirect to blog page with an error message
  }
});

// Handle blog creation
app.post("/create", ensureAuthenticated, async (req, res) => {
  try {
    const { createblog } = req.body;
    const username = req.user.username;

    // Create a new blog with the username included
    const newBlog = new Blog({
      username: username,
      createblog: createblog,
    });

    // Save the new blog to the database
    await newBlog.save();

    req.flash("success", "Blog created successfully"); // Flash success message
    res.redirect("/blog");
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error creating blog"); // Flash error message
    res.redirect("/blog");
  }
});

// Update a blog (GET request)
app.get("/update/:blogId", ensureAuthenticated, async (req, res) => {
  const blogId = req.params.blogId;
  const username = req.user.username;

  try {
    // Fetch the blog post by ID
    const blog = await Blog.findOne({ _id: blogId, username: username });

    if (!blog) {
      req.flash("error", "Blog not found");
      return res.redirect("/blog");
    }

    // Render a form to edit the blog
    res.render("update.ejs", { username: username, blog: blog });
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error fetching blog for update");
    res.redirect("/blog");
  }
});

// Update a blog (GET request)
app.get("/update/:blogId", ensureAuthenticated, async (req, res) => {
  const blogId = req.params.blogId;
  const username = req.user.username;

  try {
    // Fetch the blog post by ID
    const blog = await Blog.findOne({ _id: blogId, username: username });

    if (!blog) {
      req.flash("error", "Blog not found");
      return res.redirect("/blog");
    }

    // Render a form to edit the blog
    res.render("update.ejs", { username: username, blog: blog });
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error fetching blog for update");
    res.redirect("/blog");
  }
});

// Update a blog (POST request)
app.post("/update/:blogId", ensureAuthenticated, async (req, res) => {
  const blogId = req.params.blogId;
  const { createblog } = req.body;
  const username = req.user.username;

  try {
    // Find and update the blog by ID
    await Blog.findOneAndUpdate(
      { _id: blogId, username: username },
      { createblog: createblog }
    );

    req.flash("success", "Blog updated successfully");
    res.redirect("/blog");
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error updating blog");
    res.redirect(`/update/${blogId}`);
  }
});

// Delete a blog (GET request)
app.get("/delete/:blogId", ensureAuthenticated, async (req, res) => {
  const blogId = req.params.blogId;
  const username = req.user.username;

  try {
    // Find and delete the blog by ID
    await Blog.findOneAndDelete({ _id: blogId, username: username });

    req.flash("success", "Blog deleted successfully");
    res.redirect("/blog");
  } catch (error) {
    console.error("Error:", error);
    req.flash("error", "Error deleting blog");
    res.redirect("/blog");
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
