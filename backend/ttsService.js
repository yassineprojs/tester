const sdk = require("microsoft-cognitiveservices-speech-sdk");
const { PassThrough } = require("stream");

async function textToSpeech(text, teacher = "Ava") {
  const speechConfig = sdk.SpeechConfig.fromSubscription(
    process.env.SPEECH_KEY,
    process.env.SPEECH_REGION
  );
  speechConfig.speechSynthesisVoiceName = `ja-JP-${teacher}Neural`;
  const speechSynthesizer = new sdk.SpeechSynthesizer(speechConfig);

  const visemes = [];
  speechSynthesizer.visemeReceived = function (s, e) {
    visemes.push([e.audioOffset / 10000, e.visemeId]);
  };
  return new Promise((resolve, reject) => {
    speechSynthesizer.speakTextAsync(
      text,
      (result) => {
        const { audioData } = result;
        speechSynthesizer.close();
        const bufferStream = new PassThrough();
        bufferStream.end(Buffer.from(audioData));
        resolve({ audioStream: bufferStream, visemes });
      },
      (error) => {
        console.log(error);
        speechSynthesizer.close();
        reject(error);
      }
    );
  });
}

module.exports = { textToSpeech };
