import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

resp = client.responses.create(
    model="gpt-4o-mini",    # reliable small model
    input="You are a cybersecurity analyst. Explain this Snort alert in clear, plain English and provide 3 recommended actions.",
)

print("Response:")
print(resp.output_text)