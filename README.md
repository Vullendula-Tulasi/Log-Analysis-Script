🌟 Log File Analysis Script 🌟

📄 Description
This script processes a web server log file to provide valuable insights, including:
1️⃣ The number of requests per IP address.
2️⃣ The most frequently accessed endpoint.
3️⃣ Detection of suspicious activity based on failed login attempts.

The output is displayed in the terminal and saved as a structured CSV file for easy analysis.

✨ Features
🔍 IP Request Counts: Tracks how many requests each IP address made.
🛠️ Most Accessed Endpoint: Identifies the endpoint with the highest number of requests.
🚨 Suspicious Activity Detection: Flags IPs with failed login attempts for potential security concerns.
📂 CSV Export: Saves the results in a structured CSV file.

🛠️ Requirements
Python Version: 3.7 or higher
Required Libraries:
csv
re
