
/* ========================================
   SCRIPT.JS - URL SECURITY SCANNER FUNCTIONALITY
   ======================================== */

// ===== CONFIGURATION =====
// This is where we store the API settings that will be used to scan URLs
// Replace 'YOUR_VIRUSTOTAL_API_KEY_HERE' with your real VirusTotal API key
// apiUrl - The web address of VirusTotal's scanning service
const CONFIG = {
    apiKey: 'c300691ceb87be8d5c37f3af35709d19f39014ffeff2747755632948843714d0',
    // Put your API key here to enable real scanning
    apiUrl: 'https://www.virustotal.com/api/v3/urls'
    // This is the API endpoint where we send URLs for scanning
};

// ===== DOM ELEMENT REFERENCES =====
// These are all the HTML elements (divs, buttons, inputs) that we will control with JavaScript
// We store them in an object called 'elements' so we can easily use them in our functions
const elements = {
    // ===== INPUT CARD ELEMENTS =====
    // These are elements inside the .scanner-card div (the top card where user enters URL)

    urlInput: document.getElementById('urlInput'),
    // The text input field where user types the URL
    // HTML: <input id="urlInput" class="url-input" placeholder="Enter URL...">

    scanButton: document.getElementById('scanButton'),
    // The main blue "Scan URL" button that starts real scanning with API
    // HTML: <button id="scanButton" class="scan-button">Scan URL</button>

    simulateButton: document.getElementById('simulateButton'),
    // The "Simulate" button that shows fake demo results without API
    // HTML: <button id="simulateButton" class="secondary-button">Simulate</button>

    reanalyzeButton: document.getElementById('reanalyzeButton'),
    // The "Reanalyze" button in the header for rescanning a URL
    // HTML: <button id="reanalyzeButton" class="small-btn">Reanalyze</button>

    searchButton: document.getElementById('searchButton'),
    // The "Search" button in the header that opens VirusTotal website
    // HTML: <button id="searchButton" class="small-btn">Search</button>

    loadingSpinner: document.getElementById('loadingSpinner'),
    // The spinning circle animation shown while scanning is happening
    // HTML: <div id="loadingSpinner" class="loading-spinner"></div>

    errorMessage: document.getElementById('errorMessage'),
    // The red box that shows error messages like "Please enter a URL"
    // HTML: <div id="errorMessage" class="error-message"></div>

    // ===== RESULT CARD ELEMENTS =====
    // These are elements inside the .result-container div (the bottom card showing results)

    resultContainer: document.getElementById('resultContainer'),
    // The main results card that shows all the scan results
    // HTML: <div id="resultContainer" class="result-container">

    resultUrl: document.getElementById('resultUrl'),
    // Shows the URL that was scanned in the results
    // HTML: <div id="resultUrl" class="result-url">

    statusBadge: document.getElementById('statusBadge'),
    // Shows "SAFE" or "THREAT DETECTED" - indicates if the URL is safe or not
    // HTML: <div id="statusBadge" class="status-badge safe">SAFE</div>

    donutChart: document.getElementById('donutChart'),
    // The circular donut chart showing safety percentage visually
    // HTML: <div id="donutChart" class="donut-chart"></div>

    chartLabel: document.getElementById('chartLabel'),
    // The percentage text inside the donut chart like "75%"
    // HTML: <div id="chartLabel" class="chart-label">75%</div>

    metaStatus: document.getElementById('metaStatus'),
    // Shows HTTP status code like "200" in the meta information
    // HTML: <span id="metaStatus">200</span>

    metaType: document.getElementById('metaType'),
    // Shows content type like "text/html" in the meta information
    // HTML: <span id="metaType">text/html</span>

    metaLast: document.getElementById('metaLast'),
    // Shows when it was last scanned like "2 months ago"
    // HTML: <span id="metaLast">2 months ago</span>

    tagsRow: document.getElementById('tagsRow'),
    // Container for security tags/labels shown below meta info
    // HTML: <div id="tagsRow" class="tags-row"></div>

    // ===== TAB ELEMENTS =====
    // These are for the DETECTION, DETAILS, and COMMUNITY tabs

    tabContent: document.getElementById('tabContent'),
    // The container holding all tab panel content
    // HTML: <div id="tabContent" class="tab-content">

    tabs: document.querySelectorAll('.tab'),
    // All the tab buttons (DETECTION, DETAILS, COMMUNITY)
    // HTML: <button class="tab" data-tab="detection">DETECTION</button>

    // ===== STATISTICS ELEMENTS =====
    // These show the numbers from security vendors

    cleanCount: document.getElementById('cleanCount'),
    // Number of vendors that said the URL is safe/clean
    // HTML: <div id="cleanCount" class="stat-value">0</div>

    maliciousCount: document.getElementById('maliciousCount'),
    // Number of vendors that said the URL is malicious/dangerous
    // HTML: <div id="maliciousCount" class="stat-value">0</div>

    suspiciousCount: document.getElementById('suspiciousCount'),
    // Number of vendors that said the URL is suspicious
    // HTML: <div id="suspiciousCount" class="stat-value">0</div>

    totalScans: document.getElementById('totalScans'),
    // Total number of vendors/engines that scanned the URL
    // HTML: <div id="totalScans" class="stat-value">0</div>

    detailText: document.getElementById('detailText'),
    // Text content shown in the DETAILS tab
    // HTML: <p id="detailText" class="detail-text">No details available.</p>
};

// ===== EVENT LISTENERS SETUP =====
// These listen for when the user clicks buttons or presses keys

// When user clicks the "Scan URL" button
elements.scanButton.addEventListener('click', handleScan);
// This calls the handleScan function to start real API scanning

// When user clicks the "Simulate" button
elements.simulateButton.addEventListener('click', handleSimulate);
// This calls the handleSimulate function to show fake demo results

// When user clicks the "Reanalyze" button
elements.reanalyzeButton.addEventListener('click', handleReanalyze);
// This rescans the URL that was already scanned

// When user clicks the "Search" button
elements.searchButton.addEventListener('click', handleSearch);
// This opens the URL on the VirusTotal website for more info

// When user presses the Enter/Return key in the URL input field
elements.urlInput.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        handleScan();
        // Pressing Enter does the same thing as clicking the Scan button
    }
});

// When user clicks any tab button (DETECTION, DETAILS, or COMMUNITY)
elements.tabs.forEach(tab => {
    tab.addEventListener('click', () => {
        // Get the name of the tab from the data-tab attribute
        // For example: <button data-tab="detection">
        const tabName = tab.dataset.tab;
        switchTab(tabName);
        // This switches to show the selected tab's content
    });
});

// ===== MAIN HANDLER FUNCTIONS =====
// These are the main functions that run when user clicks buttons or enters data

/**
 * FUNCTION: handleScan()
 * PURPOSE: Scan a URL using VirusTotal API (real scanning)
 * CONNECTED TO: scanButton (id="scanButton" class="scan-button")
 * HOW IT WORKS:
 *   1. Gets the URL from the text input field
 *   2. Checks if URL is empty or invalid
 *   3. Checks if API key is configured
 *   4. Shows loading spinner
 *   5. Sends URL to VirusTotal API
 *   6. Waits for results
 *   7. Displays the results on screen
 */
async function handleScan() {
    // Get the URL from the input field and remove extra spaces
    const url = elements.urlInput.value.trim();

    // Check if the input field is empty
    if (!url) {
        showError('Please enter a URL');
        // Stop the function here if no URL
        return;
    }

    // Check if the URL format is correct (starts with http:// or https://)
    if (!isValidUrl(url)) {
        showError('Please enter a valid URL (must start with http:// or https://)');
        // Stop the function here if URL is invalid
        return;
    }

    // Check if API key has been set up
    if (CONFIG.apiKey === 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
        showError('API key not configured. Click "Simulate" to test with demo data.');
        // Stop the function here if no API key
        return;
    }

    // Show loading spinner and hide any previous errors
    setLoadingState(true);
    hideError();

    try {
        // STEP 1: Send the URL to VirusTotal for scanning
        // We still send the POST so VirusTotal has the URL, but some API setups
        // return different ids. To reliably fetch results we will use the
        // base64-encoded URL id which VirusTotal accepts for GET /urls/{id}.
        await submitUrlForScan(url);

        // STEP 2: Wait a short time for VirusTotal to process the scan
        await sleep(2000);

        // STEP 3: Compute the URL id the VirusTotal API expects for GET requests
        // This is the Base64 encoding of the URL without padding characters.
        const urlId = btoa(url).replace(/=/g, '');

        // STEP 4: Try to get the scan results using the encoded URL id
        const results = await getScanResults(urlId);

        // STEP 5: Show the results on the screen
        displayResults(url, results);
    } catch (error) {
        // If something goes wrong, show the error to the user
        console.error('Scan error:', error);
        showError(error.message || 'Failed to scan URL. Please try again.');
    } finally {
        // Hide the loading spinner whether it succeeded or failed
        setLoadingState(false);
    }
}

/**
 * FUNCTION: handleSimulate()
 * PURPOSE: Show demo/fake results without using VirusTotal API
 * CONNECTED TO: simulateButton (id="simulateButton" class="secondary-button")
 * HOW IT WORKS:
 *   1. Gets the URL from input (or uses default)
 *   2. Creates fake demo results
 *   3. Shows those fake results like they came from real scanning
 *   This is useful for testing when you don't have an API key
 */
function handleSimulate() {
    // Get the URL from input field, or use a default example
    const url = elements.urlInput.value.trim() || 'https://example.com';

    // Check if the URL format is valid
    if (!isValidUrl(url)) {
        showError('Please enter a valid URL');
        return;
    }

    // Show the loading spinner to simulate scanning time
    setLoadingState(true);
    hideError();

    // Wait 1.5 seconds then show results (to make it feel real)
    setTimeout(() => {
        // Create fake demo results
        const demoResults = generateDemoResults();
        // Display those fake results
        displayResults(url, demoResults);
        // Hide the loading spinner
        setLoadingState(false);
    }, 1500);
}

/**
 * FUNCTION: handleReanalyze()
 * PURPOSE: Rescan the URL that was already scanned
 * CONNECTED TO: reanalyzeButton (id="reanalyzeButton" class="small-btn")
 * HOW IT WORKS:
 *   1. Gets the URL from the results display
 *   2. Puts it back into the input field
 *   3. Runs the simulate function to show results again
 */
function handleReanalyze() {
    // Get the URL that is currently displayed in the results
    const url = elements.resultUrl.textContent.trim();

    // Check if there is a URL to rescan (not the default example)
    if (url && url !== 'https://example.com') {
        // Put the URL back in the input field
        elements.urlInput.value = url;
        // Scan it again using the simulate function
        handleSimulate();
    } else {
        // Show error if no URL was scanned yet
        showError('Please scan a URL first');
    }
}

/**
 * FUNCTION: handleSearch()
 * PURPOSE: Open the current URL on VirusTotal website for more details
 * CONNECTED TO: searchButton (id="searchButton" class="small-btn")
 * HOW IT WORKS:
 *   1. Gets the URL from the results
 *   2. Opens a new browser tab
 *   3. Shows the full VirusTotal report for that URL
 */
function handleSearch() {
    // Get the URL that is currently displayed in the results
    const url = elements.resultUrl.textContent.trim();

    // Check if there is a URL to search (not the default example)
    if (url && url !== 'https://example.com') {
        // Open the VirusTotal website in a new tab with the URL
        window.open(`https://www.virustotal.com/gui/search/${encodeURIComponent(url)}`, '_blank');
    } else {
        // Show error if no URL was scanned yet
        showError('Please scan a URL first');
    }
}

// ===== API FUNCTIONS =====
// These functions talk to the VirusTotal API to get scan information

/**
 * FUNCTION: submitUrlForScan(url)
 * PURPOSE: Send a URL to VirusTotal API to be scanned
 * TAKES: url - the website address to scan
 * RETURNS: A response object from VirusTotal with scan ID
 * CONNECTED TO: Used by handleScan() function
 * HOW IT WORKS:
 *   1. Creates a request to VirusTotal's API
 *   2. Includes the API key for authentication
 *   3. Sends the URL for scanning
 *   4. Gets back an ID for the scan
 */
async function submitUrlForScan(url) {
    // Create a request to VirusTotal's API
    const response = await fetch(CONFIG.apiUrl, {
        method: 'POST',
        // POST means we are sending/uploading data to the API
        headers: {
            // Headers are extra information we send to the API
            'x-apikey': CONFIG.apiKey,
            // This is our secret API key that proves we're authorized
            'Content-Type': 'application/x-www-form-urlencoded'
            // This tells the API what format our data is in
        },
        body: `url=${encodeURIComponent(url)}`
        // The actual data - the URL we want to scan
    });

    // Check if the request failed
    if (!response.ok) {
        // If response is not ok (like 404 or 500 error)
        throw new Error(`API Error: ${response.status}`);
        // Throw an error so handleScan() can catch it
    }

    // Convert the response to a JavaScript object and return it
    return await response.json();
}

/**
 * FUNCTION: getScanResults(urlId)
 * PURPOSE: Get the scan results after VirusTotal has processed the URL
 * TAKES: urlId - the ID of the scan we want results for
 * RETURNS: A response object containing all the scan results
 * CONNECTED TO: Used by handleScan() function
 * HOW IT WORKS:
 *   1. Creates a request to get results using the scan ID
 *   2. Includes the API key for authentication
 *   3. Gets back the detailed results from all security vendors
 *   4. Returns all the detection statistics
 */
async function getScanResults(urlId) {
    // Create a request to get the results
    const response = await fetch(`${CONFIG.apiUrl}/${urlId}`, {
        method: 'GET',
        // GET means we are asking for data, not sending it
        headers: {
            // Headers with authentication info
            'x-apikey': CONFIG.apiKey
            // Our secret API key
        }
    });

    // Check if the request failed
    if (!response.ok) {
        // If response is not ok (like 404 or 500 error)
        throw new Error(`Failed to get results: ${response.status}`);
        // Throw an error so handleScan() can catch it
    }

    // Convert the response to a JavaScript object and return it
    return await response.json();
}

// ===== DISPLAY FUNCTIONS =====
// These functions show the scan results to the user

/**
 * FUNCTION: displayResults(url, data)
 * PURPOSE: Takes the scan results and displays them on the screen
 * TAKES: 
 *   - url: the URL that was scanned
 *   - data: the results from VirusTotal API or demo data
 * CONNECTED TO:
 *   - resultUrl (id="resultUrl" class="result-url")
 *   - statusBadge (id="statusBadge" class="status-badge")
 *   - donutChart (id="donutChart" class="donut-chart")
 *   - chartLabel (id="chartLabel" class="chart-label")
 *   - cleanCount, maliciousCount, suspiciousCount, totalScans (stat-value)
 *   - metaStatus, metaType, metaLast (metadata spans)
 *   - tagsRow (id="tagsRow" class="tags-row")
 *   - detailText (id="detailText" class="detail-text")
 *   - resultContainer (id="resultContainer" class="result-container")
 * HOW IT WORKS:
 *   1. Extracts the detection statistics from the scan data
 *   2. Calculates safe percentage
 *   3. Updates all the HTML elements with the results
 *   4. Shows the results card
 */
function displayResults(url, data) {
    // Extract the statistics from the API or demo data
    let stats;
    if (data.stats) {
        // If it's demo data
        stats = data.stats;
    } else {
        // If it's real API data
        stats = data.data.attributes.last_analysis_stats;
    }

    // Extract the count of each type of detection
    const malicious = stats.malicious || 0;
    // How many security vendors said it's malicious (dangerous)
    const suspicious = stats.suspicious || 0;
    // How many security vendors said it's suspicious
    const clean = stats.harmless || stats.clean || 0;
    // How many security vendors said it's safe/harmless
    const total = malicious + suspicious + clean;
    // Total number of vendors that scanned it

    // Calculate what percentage is safe (0 to 100)
    const safePercentage = total > 0 ? Math.round((clean / total) * 100) : 0;
    // Convert percentage to degrees (0 to 360) for the donut chart
    const safeAngle = (safePercentage / 100) * 360;
    // Determine if the URL is safe (only if no malicious or suspicious)
    const isSafe = malicious === 0 && suspicious === 0;

    // ===== UPDATE RESULT URL =====
    // Connected to: resultUrl (id="resultUrl" class="result-url" in url-row div)
    elements.resultUrl.textContent = url;
    // Shows the URL that was scanned

    // ===== UPDATE STATUS BADGE =====
    // Connected to: statusBadge (id="statusBadge" class="status-badge")
    elements.statusBadge.textContent = isSafe ? 'SAFE' : 'THREAT DETECTED';
    // Shows "SAFE" if no threats, "THREAT DETECTED" if there are threats
    elements.statusBadge.className = `status-badge ${isSafe ? 'safe' : 'danger'}`;
    // Applies 'safe' class (green) or 'danger' class (red) from style.css

    // ===== UPDATE DONUT CHART =====
    // Connected to: donutChart (id="donutChart" class="donut-chart")
    elements.donutChart.style.setProperty('--safe-angle', `${safeAngle}deg`);
    // Updates the CSS variable that controls the chart's visual appearance
    // Connected to: chartLabel (id="chartLabel" class="chart-label")
    elements.chartLabel.textContent = `${safePercentage}%`;
    // Shows the percentage in the middle of the chart
    elements.chartLabel.style.color = isSafe ? 'var(--color-safe)' : 'var(--color-danger)';
    // Makes the percentage green if safe, red if not safe

    // ===== UPDATE METADATA =====
    // Connected to: metaStatus (id="metaStatus" span in meta-row)
    elements.metaStatus.textContent = '200';
    // HTTP status code (200 means OK/success)
    // Connected to: metaType (id="metaType" span in meta-row)
    elements.metaType.textContent = 'text/html';
    // Content type of the website
    // Connected to: metaLast (id="metaLast" span in meta-row)
    elements.metaLast.textContent = '2 months ago';
    // When it was last scanned

    // ===== UPDATE TAGS =====
    // Connected to: tagsRow (id="tagsRow" class="tags-row")
    updateTags(isSafe, malicious, suspicious);
    // Function that creates tag elements based on the scan results

    // ===== UPDATE STATISTICS GRID =====
    // Connected to: cleanCount (id="cleanCount" class="stat-value")
    elements.cleanCount.textContent = clean;
    // Connected to: maliciousCount (id="maliciousCount" class="stat-value")
    elements.maliciousCount.textContent = malicious;
    // Connected to: suspiciousCount (id="suspiciousCount" class="stat-value")
    elements.suspiciousCount.textContent = suspicious;
    // Connected to: totalScans (id="totalScans" class="stat-value")
    elements.totalScans.textContent = total;

    // ===== UPDATE DETAILS TAB TEXT =====
    // Connected to: detailText (id="detailText" class="detail-text" in DETAILS tab)
    const detectionText = `
        Analysis Summary:
        • Clean Detections: ${clean}
        • Malicious Detections: ${malicious}
        • Suspicious Detections: ${suspicious}
        • Total Scans: ${total}
        
        ${isSafe ? 'No security vendors flagged this URL as malicious.' : 'This URL has been flagged by one or more security vendors.'}
    `;
    elements.detailText.textContent = detectionText;
    // Shows detailed information in the DETAILS tab

    // ===== SHOW THE RESULTS CONTAINER =====
    // Connected to: resultContainer (id="resultContainer" class="result-container")
    showResults();
    // Makes the results card visible to the user

    // Switch to the DETECTION tab to show the first set of results
    switchTab('detection');
}

/**
 * FUNCTION: generateDemoResults()
 * PURPOSE: Create fake scan results for testing without an API
 * RETURNS: An object with fake detection statistics
 * CONNECTED TO: Used by handleSimulate() function
 * HOW IT WORKS:
 *   1. Uses random numbers to create different scenarios
 *   2. Returns fake stats like they came from real scanning
 *   3. Creates 3 different types of results:
 *      - Safe URLs (60% chance)
 *      - Suspicious URLs (25% chance)
 *      - Malicious URLs (15% chance)
 */
function generateDemoResults() {
    // Generate a random number between 0 and 1
    const random = Math.random();

    if (random < 0.6) {
        // 60% chance: Return fake data for a SAFE URL
        return {
            stats: {
                malicious: 0,
                // 0 vendors said it's malicious
                suspicious: 0,
                // 0 vendors said it's suspicious
                harmless: 85,
                // 85 vendors said it's safe
                clean: 85
                // Same as harmless
            }
        };
    } else if (random < 0.85) {
        // 25% chance: Return fake data for a SUSPICIOUS URL
        return {
            stats: {
                malicious: 0,
                // 0 vendors said it's malicious
                suspicious: 3,
                // 3 vendors said it's suspicious
                harmless: 82,
                // 82 vendors said it's safe
                clean: 82
            }
        };
    } else {
        // 15% chance: Return fake data for a MALICIOUS URL
        return {
            stats: {
                malicious: 5,
                // 5 vendors said it's malicious
                suspicious: 2,
                // 2 vendors said it's suspicious
                harmless: 78,
                // 78 vendors said it's safe
                clean: 78
            }
        };
    }
}

/**
 * FUNCTION: updateTags(isSafe, malicious, suspicious)
 * PURPOSE: Create and display security category tags
 * TAKES:
 *   - isSafe: boolean (true if URL is safe, false if not)
 *   - malicious: number of malicious detections
 *   - suspicious: number of suspicious detections
 * CONNECTED TO: tagsRow (id="tagsRow" class="tags-row" div)
 * HOW IT WORKS:
 *   1. Clears any old tags
 *   2. Creates new tag elements based on the scan results
 *   3. Displays tags like "safe", "malicious", "trackers", etc.
 *   4. Each tag is styled with a tag class from style.css
 */
function updateTags(isSafe, malicious, suspicious) {
    // Remove all old tag elements from the tags row
    elements.tagsRow.innerHTML = '';

    // Create an array to store tag names
    const tags = [];

    if (isSafe) {
        // If the URL is safe, add these tags
        tags.push('safe');
        // Add the "safe" tag
        tags.push('external-resources');
        // Add "external-resources" tag
    } else {
        // If the URL is not safe, add these tags
        if (malicious > 0) {
            tags.push('malicious');
            // Add "malicious" tag if there are malicious detections
        }
        if (suspicious > 0) {
            tags.push('suspicious');
            // Add "suspicious" tag if there are suspicious detections
        }
        tags.push('trackers');
        // Add "trackers" tag
    }

    // Loop through each tag name and create a tag element for it
    tags.forEach(tagText => {
        // Create a new span element
        const tag = document.createElement('span');
        // Set its class to "tag" (styled in style.css)
        tag.className = 'tag';
        // Set the text content to the tag name
        tag.textContent = tagText;
        // Add this new tag element to the tags row
        elements.tagsRow.appendChild(tag);
    });
}

/**
 * FUNCTION: switchTab(tabName)
 * PURPOSE: Switch between different result tabs (DETECTION, DETAILS, COMMUNITY)
 * TAKES: tabName - the name of the tab to show (like "detection", "details", "community")
 * CONNECTED TO:
 *   - .tab buttons (class="tab" with data-tab attribute)
 *   - .tab-panel divs (class="tab-panel" with ids like "detection", "details", "community")
 * HOW IT WORKS:
 *   1. Updates all tab buttons to show which one is active
 *   2. Hides all tab content panels
 *   3. Shows only the selected tab's content
 *   This creates the switching effect when user clicks different tabs
 */
function switchTab(tabName) {
    // Loop through all tab buttons
    elements.tabs.forEach(tab => {
        // Check if this button's data-tab matches the requested tab
        if (tab.dataset.tab === tabName) {
            // Add 'active' class to make this button look selected
            tab.classList.add('active');
        } else {
            // Remove 'active' class from other buttons
            tab.classList.remove('active');
        }
    });

    // Get all the tab panel divs (the content areas)
    const panels = elements.tabContent.querySelectorAll('.tab-panel');
    // Loop through all panels
    panels.forEach(panel => {
        // Check if this panel's ID matches the requested tab
        if (panel.id === tabName) {
            // Add 'active' class to show this panel
            panel.classList.add('active');
        } else {
            // Remove 'active' class to hide other panels
            panel.classList.remove('active');
        }
    });
}

// ===== UI STATE CONTROL FUNCTIONS =====
// These functions control what the user sees on the screen

/**
 * FUNCTION: setLoadingState(isLoading)
 * PURPOSE: Show or hide the loading spinner and disable buttons
 * TAKES: isLoading - true to show loading, false to hide it
 * CONNECTED TO:
 *   - scanButton (id="scanButton" class="scan-button")
 *   - simulateButton (id="simulateButton" class="secondary-button")
 *   - loadingSpinner (id="loadingSpinner" class="loading-spinner")
 * HOW IT WORKS:
 *   1. Disables the scan button when loading starts
 *   2. Changes button text to "Scanning..." or "Scan URL"
 *   3. Shows/hides the spinning animation
 */
function setLoadingState(isLoading) {
    // Disable or enable the scan button
    elements.scanButton.disabled = isLoading;
    // Disable or enable the simulate button
    elements.simulateButton.disabled = isLoading;
    // Change the button text based on loading state
    elements.scanButton.textContent = isLoading ? 'Scanning...' : 'Scan URL';

    // Show or hide the spinning loader animation
    if (isLoading) {
        // Add 'show' class to make the spinner visible
        elements.loadingSpinner.classList.add('show');
    } else {
        // Remove 'show' class to hide the spinner
        elements.loadingSpinner.classList.remove('show');
    }
}

/**
 * FUNCTION: showResults()
 * PURPOSE: Make the results card visible to the user
 * CONNECTED TO: resultContainer (id="resultContainer" class="result-container")
 * HOW IT WORKS:
 *   1. Adds the 'show' class to the results container
 *   2. CSS shows the element with animation
 *   The CSS in style.css controls the visibility
 */
function showResults() {
    // Add 'show' class to make the results card visible
    elements.resultContainer.classList.add('show');
}

/**
 * FUNCTION: hideResults()
 * PURPOSE: Hide the results card (make it invisible)
 * CONNECTED TO: resultContainer (id="resultContainer" class="result-container")
 * HOW IT WORKS:
 *   1. Removes the 'show' class from the results container
 *   2. CSS hides the element
 */
function hideResults() {
    // Remove 'show' class to hide the results card
    elements.resultContainer.classList.remove('show');
}

/**
 * FUNCTION: showError(message)
 * PURPOSE: Display an error message to the user
 * TAKES: message - the error text to show (like "Please enter a URL")
 * CONNECTED TO: errorMessage (id="errorMessage" class="error-message" div)
 * HOW IT WORKS:
 *   1. Sets the text content of the error message
 *   2. Adds the 'show' class to make it visible
 *   3. The error box appears in red under the scan button
 */
function showError(message) {
    // Set the error text
    elements.errorMessage.textContent = message;
    // Add 'show' class to make it visible
    elements.errorMessage.classList.add('show');
}

/**
 * FUNCTION: hideError()
 * PURPOSE: Hide the error message
 * CONNECTED TO: errorMessage (id="errorMessage" class="error-message" div)
 * HOW IT WORKS:
 *   1. Removes the 'show' class
 *   2. Error message becomes invisible
 */
function hideError() {
    // Remove 'show' class to hide the error message
    elements.errorMessage.classList.remove('show');
}

// ===== UTILITY HELPER FUNCTIONS =====
// These are small helper functions used throughout the code

/**
 * FUNCTION: isValidUrl(string)
 * PURPOSE: Check if a URL is in the correct format
 * TAKES: string - the text to check
 * RETURNS: true if valid URL, false if not
 * USED BY: handleScan() and handleSimulate() functions
 * HOW IT WORKS:
 *   1. Tries to create a URL object from the string
 *   2. Checks if it starts with http:// or https://
 *   3. Returns true only if both checks pass
 */
function isValidUrl(string) {
    try {
        // Try to create a URL object from the string
        // This will throw an error if the URL format is wrong
        const url = new URL(string);
        // Check if the protocol is http or https
        return url.protocol === 'http:' || url.protocol === 'https:';
        // Return true only if it's http or https
    } catch {
        // If an error is thrown, the URL is invalid
        return false;
    }
}

/**
 * FUNCTION: sleep(ms)
 * PURPOSE: Wait (pause) for a certain amount of time
 * TAKES: ms - number of milliseconds to wait (1000 = 1 second)
 * RETURNS: A promise that resolves after the time passes
 * USED BY: handleScan() function to wait between API calls
 * HOW IT WORKS:
 *   1. Creates a new Promise
 *   2. Sets a timeout to resolve after the specified time
 *   3. Can be used with 'await' to pause code execution
 *   EXAMPLE: await sleep(2000); // waits 2 seconds
 */
function sleep(ms) {
    // Return a new promise that resolves after ms milliseconds
    return new Promise(resolve => setTimeout(resolve, ms));
}

