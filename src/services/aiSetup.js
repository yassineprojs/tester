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

export const getTextToSpeech = async (text, teacher = "Ava") => {
  const response = await fetch(`${API_URL}/text-to-speech`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text, teacher }),
  });

  if (!response.ok) {
    throw new Error("Text-to-speech request failed");
  }

  const audioBlob = await response.blob();
  const visemes = JSON.parse(response.headers.get("Visemes"));
  return { audioBlob, visemes };
};
