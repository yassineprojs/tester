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
    const response = await axios.post(
      "http://localhost:5000/analyse",
      {
        url: req.body.url,
      },
      {
        timeout: 60000, // Set timeout to 60 seconds
      }
    );
    res.json(response.data);
  } catch (error) {
    console.error("Error:", error);
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error(error.response.data);
      console.error(error.response.status);
      console.error(error.response.headers);
    } else if (error.request) {
      // The request was made but no response was received
      console.error(error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error("Error", error.message);
    }
    res.status(500).json({
      error: "An error occurred",
      details: error.message,
      additionalInfo: error.response
        ? error.response.data
        : "No additional info",
    });
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
