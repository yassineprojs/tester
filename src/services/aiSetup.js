import { context } from "@react-three/fiber";

const API_URL = "http://localhost:3000";

export const analyseCurrentPage = async () => {
  const url = window.location.href;
  // Send a POST request to the local server with the url of the active tab
  const response = await fetch(`${API_URL}/security-check`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });
  return response.json();
};

export const askAI = async (question, context) => {
  const response = await fetch(`${API_URL}/ask-ai`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ question, context }),
  });
  return response.text();
};

// const anthropic = new Anthropic({
//   apiKey: process.env["ANTHROPIC_API_KEY"],
// });

// const msg = await anthropic.messages.create({
//   model: "claude-3-5-sonnet-20240620",
//   max_tokens: 1024,
//   system:
//     "You are a Website Security Advisor AI. Your role is to inform users about potential risks and vulnerabilities of websites, providing clear and actionable advice to enhance their security.",
//   messages: [
//     {
//       role: "assistant",
//       content: "Hi, I'm your assistant for today. How can I help you?",
//     },
//   ],
// });
// console.log(msg);
