import { create } from "zustand";
import { askAI, getTextToSpeech } from "../services/aiSetup.js";

export const useAIAssistant = create((set, get) => ({
  messages: [],
  currentMessage: null,
  assistant: "Ava", // Default assistant
  loading: false,

  setassistant: (assistant) => set({ assistant }),

  askAI: async (question, context) => {
    if (!question) return;

    set({ loading: true });

    try {
      const answer = await askAI(question, context);
      const message = { question, answer, id: get().messages.length };

      set((state) => ({
        messages: [...state.messages, message],
        currentMessage: message,
      }));

      await get().playMessage(message);
    } catch (error) {
      console.error("Error asking AI:", error);
    } finally {
      set({ loading: false });
    }
  },

  playMessage: async (message) => {
    set({ currentMessage: message, loading: true });

    if (!message.audioPlayer) {
      try {
        const { audioBlob, visemes } = await getTextToSpeech(
          message.answer,
          get().assistant
        );
        const audioUrl = URL.createObjectURL(audioBlob);
        const audioPlayer = new Audio(audioUrl);

        audioPlayer.onended = () => set({ currentMessage: null });

        message.audioPlayer = audioPlayer;
        message.visemes = visemes;

        set((state) => ({
          messages: state.messages.map((m) =>
            m.id === message.id ? message : m
          ),
        }));
      } catch (error) {
        console.error("Error getting TTS:", error);
      } finally {
        set({ loading: false });
      }
    }

    message.audioPlayer.currentTime = 0;
    await message.audioPlayer.play();
  },

  stopMessage: () => {
    const { currentMessage } = get();
    if (currentMessage && currentMessage.audioPlayer) {
      currentMessage.audioPlayer.pause();
      set({ currentMessage: null });
    }
  },
}));
