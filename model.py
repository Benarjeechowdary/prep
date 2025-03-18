import google.generativeai as genai
model=genai.GenerativeModel(model_name="gemini-1.5-flash")

# OpenAI API Key
api_key1 = "AIzaSyDiF3G98dWgoXvOo0FIGI4OgVxVxhpFU7U"
genai.configure(api_key=api_key1)
def generate_output(user_answer):
    """Generate follow-up question using OpenAI API."""
    prompt = f"You are an AI interviewer. Based on this answer: '{user_answer}', ask a follow-up question."

    response = model.generate_content([prompt])

    return response.text