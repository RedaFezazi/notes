// app.js
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const NeDB = require("nedb");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;
const bcrypt = require("bcrypt");
const JWT_SECRET = "You Shall Pass...Maybe";
const db = new NeDB({ filename: "notes.db", autoload: true });

const swaggerUi = require("swagger-ui-express");
const swaggerDocument = require("./swagger.json");

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(bodyParser.json());

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    console.log(err);
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Endpoint to create an account
app.post("/api/user/signup", (req, res) => {
  const { username, password } = req.body;

  // Check if username or password is missing
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  // Hash the password
  const saltRounds = 10;
  bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
    if (err) {
      console.error("Error hashing password:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    // Store the user's information (username and hashed password) in your database
    db.insert(
      { username, password: hashedPassword, notes: [] },
      (err, newUser) => {
        if (err) {
          console.error("Error creating user:", err);
          return res.status(500).json({ message: "Internal server error" });
        }

        res.status(201).json({ message: "User created successfully" });
      }
    );
  });
});

// Endpoint to login
app.post("/api/user/login", (req, res) => {
  const { username, password } = req.body;
  // Check if username or password is missing
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  // Find the user in the database by username
  db.findOne({ username }, (err, user) => {
    if (err) {
      console.error("Error finding user:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    // If user not found, return error
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Compare the password provided with the hashed password stored in the database
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      // If passwords match, generate JWT token
      if (result) {
        const token = jwt.sign({ username: user.username }, JWT_SECRET);
        return res.status(200).json({ message: "Login successful", token });
      } else {
        // If passwords don't match, return error
        return res
          .status(401)
          .json({ message: "Invalid username or password" });
      }
    });
  });
});

// Endpoints requiring authentication
app.use(authenticateToken);

app.get("/api/notes", (req, res) => {
  // Find the user by username
  db.findOne({ username: req.user.username }, (err, user) => {
    if (err) {
      console.error("Error finding user:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    // Extract and return the notes from the user document
    const notes = user.notes;
    if (notes.length === 0) {
      res.status(404).json({ message: "No notes found" });
    } else {
      res.status(200).json(notes);
    }
  });
});

// Endpoint to save a note
app.post("/api/notes", (req, res) => {
  const { title, content } = req.body;

  // Check if title or content is missing
  if (!title || !content) {
    return res.status(400).json({ message: "Title and content are required" });
  }

  const note = {
    id: uuidv4(),
    title,
    content,
    createdAt: new Date(), // Set creation date
    modifiedAt: new Date(), // Set modification date initially same as creation date
  };

  db.update(
    { username: req.user.username }, // Find the user by username
    { $push: { notes: note } }, // Push the new note into the notes array
    (err) => {
      if (err) {
        console.error("Error saving note:", err);
        return res.status(500).json({ message: "Internal server error" });
      }
      res.status(201).json({
        message: "Note saved successfully",
        note: note,
      });
    }
  );
});

app.put("/api/notes/:id", (req, res) => {
  const noteId = req.params.id;
  const updatedNoteData = req.body;

  // Find the note by its ID
  db.findOne({ "notes.id": noteId }, (err, document) => {
    if (err) {
      console.error("Error finding note:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (!document) {
      return res.status(404).json({ message: "Note not found" });
    }
    // Update the note's fields
    document.notes.forEach((n, index) => {
      if (n.id === noteId) {
        document.notes[index].title = updatedNoteData.title;
        document.notes[index].content = updatedNoteData.content;
        document.notes[index].modifiedAt = new Date();
      }
    });

    // Save the updated note back to the database
    db.update({ _id: document._id }, document, {}, (err, numAffected) => {
      if (err) {
        console.error("Error updating note:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      res.status(200).json({ message: "Note updated successfully" });
    });
  });
});

app.delete("/api/notes/:id", (req, res) => {
  const noteId = req.params.id;

  // Find the document containing the note
  db.findOne({ "notes.id": noteId }, (err, doc) => {
    if (err) {
      console.error("Error finding note:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (!doc) {
      return res.status(404).json({ message: "Note not found" });
    }

    // Remove the note from the notes array
    doc.notes = doc.notes.filter((note) => note.id !== noteId);

    // Save the updated document back to the database
    db.update({ _id: doc._id }, doc, {}, (err) => {
      if (err) {
        console.error("Error deleting note:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      res.status(200).json({ message: "Note deleted successfully" });
    });
  });
});

// Endpoint to search notes by title (extra credit)
// app.get("/api/notes/search", (req, res) => {
// Implement search logic here
// });

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
