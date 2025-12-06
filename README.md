# URL-Safety-Scanner
# 🔍 URL Security Scanner

A front-end cybersecurity tool designed to analyze URLs for potential threats, phishing attempts, and malware. This application provides a user-friendly interface to interact with the VirusTotal API, offering detailed security reports and visual safety metrics.

## 🚀 Project Overview

This project is a web-based scanner that allows users to input a website URL and receive an immediate safety assessment. It bridges the gap between complex security data and a clean, understandable UI.

I built this project to demonstrate:
* **API Integration:** Handling asynchronous requests (`async/await`) to the VirusTotal v3 API.
* **DOM Manipulation:** Dynamically updating charts, status badges, and statistics without reloading the page.
* **Cyber-Aesthetic UI:** A responsive, dark-mode design using modern CSS variables and animations.

## ✨ Key Features

* **Real-Time Scanning:** Connects to the VirusTotal API to fetch live threat reports from over 80+ security vendors.
* **Simulation Mode:** Includes a "Simulate" feature that generates realistic demo data (Safe, Suspicious, or Malicious scenarios) for testing the UI without an API key.
* **Visual Data Visualization:**
    * Dynamic Donut Chart showing the safety score.
    * Status Badges (Safe vs. Threat Detected).
    * Categorized tags (Malicious, Trackers, External Resources).
* **Detailed Metrics:** Displays specific counts for harmless, malicious, and suspicious flags.
* **Responsive Design:** Fully functional on desktop and mobile devices.

## 🛠️ Technologies Used

* **HTML5:** Semantic structure.
* **CSS3:** Custom styling with CSS Variables, Flexbox, Grid, and Animations (No frameworks used).
* **JavaScript (ES6+):** Vanilla JS for logic, API handling, and UI state management.

## ⚙️ How to Use

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/your-username/your-repo-name.git](https://github.com/your-username/your-repo-name.git)
    ```
2.  **Open `index.html`** in your browser.
3.  **Simulation Mode (Default):**
    * Click the **"Simulate"** button to see how the application visualizes different security states (Safe, Suspicious, or Malicious) without needing an API key.
4.  **Real Scanning (Configuration Required):**
    * Obtain a free API Key from [VirusTotal](https://www.virustotal.com/).
    * Open `script.js` and locate the `CONFIG` object at the top.
    * Replace the placeholder with your key:
        ```javascript
        const CONFIG = {
            apiKey: 'YOUR_ACTUAL_API_KEY_HERE', 
            apiUrl: '[https://www.virustotal.com/api/v3/urls](https://www.virustotal.com/api/v3/urls)'
        };
        ```
    * Enter a URL and click **"Scan URL"**.

## 📸 Screenshots

*(You can add a screenshot of your project here by dragging an image into your GitHub issue editor or creating an assets folder)*

## 🔮 Future Improvements

* Add a backend (Node.js) to hide the API key for production deployment.
* Implement a history log to show previously scanned URLs.
* Add export functionality to save scan reports as PDF.

---
*Created by [Muhammad Rohail Tariq]*
