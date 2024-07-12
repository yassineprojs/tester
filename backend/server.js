require("dotenv").config({ path: "../.env" });
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const Anthropic = require("@anthropic-ai/sdk");
const textToSpeech = require("./ttsService");

const PORT = 3000;

const app = express();
app.use(cors());
app.use(express.json());

const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

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

app.post("/ask-ai", async (req, res) => {
  try {
    const { question, context } = req.body;
    const response = await anthropic.messages.create({
      model: "claude-3-sonnet-20240229",
      max_tokens: 1024,
      system:
        "You are a Website Security Advisor AI. Your role is to inform users about potential risks and vulnerabilities of websites, providing clear and actionable advice to enhance their security. Use the provided security analysis context to answer user questions.",
      messages: [
        {
          role: "user",
          content: `Security analysis context: ${context}\n\nUser question: ${question}`,
        },
      ],
    });
    res.send(response.content[0].text);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/text-to-speech", async (req, res) => {
  try {
    const { text, teacher } = req.body;
    const { audioStream, visemes } = await textToSpeech(text, teacher);

    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Content-Disposition", "inline; filename=tts.mp3");
    res.setHeader("Visemes", JSON.stringify(visemes));

    audioStream.pipe(res);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.listen(PORT, () => {
  console.log(`Node.js backend listening on port ${PORT}`);
});
