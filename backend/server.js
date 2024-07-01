const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

app.post("/security-check", async (req, res) => {
  console.log("Received request:", req.body);
  try {
    const response = await axios.post("http://localhost:5000/analyse", {
      url: req.body.url,
    });
    res.json(response.data);
  } catch (error) {
    console.error("Error:", error);
    res
      .status(500)
      .json({ error: "An error occurred", details: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Node.js backend listening on port ${PORT}`);
});
