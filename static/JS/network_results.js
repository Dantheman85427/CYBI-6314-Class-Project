function showLoading() {
    document.getElementById('loading').style.display = 'block';
    document.getElementById('pcap-upload').disabled = true;
}

document.getElementById('upload-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    showLoading();
    
    const fileInput = document.getElementById('pcap-upload');
    const file = fileInput.files[0];
    
    if (!file) {
        alert('Please select a PCAP file');
        document.getElementById('loading').style.display = 'none';
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    
    // Debug: Log FormData contents
    for (let [key, value] of formData.entries()) {
        console.log(key, value);
    }
    
    try {
        const response = await fetch('/Homepage/Network_Classifier/upload', {
            method: 'POST',
            body: formData
            // Don't set Content-Type header - let the browser set it automatically
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Server error: ${response.status} - ${errorText}`);
        }
        
        const data = await response.json();
        displayResults(data);
    } catch (error) {
        console.error('Upload error:', error);
        alert(error.message);
    } finally {
        document.getElementById('loading').style.display = 'none';
    }
});

function displayResults(data) {
    const container = document.getElementById('results-container');
    container.style.display = 'block';
	
    // Always show download link
    const downloadLink = data.download_path ? `
        <p><a href="${data.download_path}" class="btn btn-primary btn-sm" download>
            Download Full Analysis Results
        </a></p>
        ${data.total_time ? `<small class="text-muted">Analysis completed in ${data.total_time.toFixed(2)} seconds</small>` : ''}
    ` : '';
	
    // Safely handle undefined values
    const threatType = data.threat_type || 'BENIGN';
    const totalFlows = data.total_flows || 0;
    const maliciousCount = data.malicious_count || 0;
    const accuracy = data.accuracy ? `${(data.accuracy * 100).toFixed(1)}%` : '0%';
	const visualizations = data.visualizations || {};
	const hasMalicious = data.malicious_flows && data.malicious_flows.length > 0;
	
	console.log("Full response data:", data);
	console.log("Visualization data:", visualizations);
	
    const setImage = (elementId, path) => {
        const imgElement = document.getElementById(elementId);
        const container = imgElement.closest('.col-md-6');
        
        if(path) {
            // Construct full URL if it's a relative path
            const fullPath = path.startsWith('/') ? path : `/${path}`;
            imgElement.src = fullPath;
            container.style.display = 'block';
            
            // Add cache busting to prevent browser caching
            imgElement.src = fullPath + '?t=' + new Date().getTime();
        } else {
            container.style.display = 'none';
        }
    };
    
    setImage('feature-impact-img', visualizations.feature_impact);
    setImage('flow-heatmap-img', visualizations.flow_heatmap);
    setImage('protocol-dist-img', visualizations.protocol_dist);
    setImage('malicious-timeline-img', visualizations.malicious_timeline);
    
    // Summary Card
    const summaryCard = document.getElementById('summary-card');
    summaryCard.innerHTML = `
        <div class="card ${hasMalicious ? 'bg-danger' : 'bg-success'} text-white">
            <div class="card-body">
                <h4>${hasMalicious ? 'Ã¢Å¡ Ã¯Â¸Â Malicious Activity Detected' : 'Ã¢Å“â€¦ No Threats Found'}</h4>
                <p>Analyzed ${totalFlows} network flows</p>
                ${hasMalicious ? `
                    <p>${maliciousCount} malicious flows detected (${accuracy} confidence)</p>
                    <p>Primary threat type: ${threatType}</p>
                ` : ''}
				${downloadLink}
            </div>
        </div>
    `;
    // Details Table
    const table = document.getElementById('details-table');
    if (data.malicious_flows && data.malicious_flows.length > 0) {
        table.innerHTML = `
            <h2>Malicious Network Flows</h2>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Source IP/Port</th>
                            <th>Destination IP/Port</th>
                            <th>Protocol</th>
                            <th>Stacked Ensemble Results</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.malicious_flows.map(flow => `
                            <tr>
                                <td>${flow.timestamp || ''}</td>
                                <td>${flow.src_ip || ''} : ${flow.src_port || ''}</td>
                                <td>${flow.dst_ip || ''} : ${flow.dst_port || ''}</td>
                                <td>${getProtocolName(flow.protocol)}</td>
                                <td>${flow.prediction || ''} (${(flow.confidence * 100).toFixed(1)}%)</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    } else {
        table.innerHTML = '<p> No malicious flows detected</p>';
    }
    // Add visualization section
    // if (data.feat_path) {
        // container.innerHTML += `
            // <div class="card mt-4">
                // <div class="card-body">
                    // <h4>Feature Analysis</h4>
                    // <img src="${data.feat_path}" class="img-fluid" alt="Feature Importance">
                // </div>
            // </div>
        // `;
    // }
}


function getProtocolName(protoNum) {
    const protocols = {
        0: 'IP',
        1: 'ICMP',
        2: 'IGMP', 
        3: 'GGP',
        4: 'IPv4',
        6: 'TCP',
        8: 'EGP',
        12: 'PUP',
        17: 'UDP',
        20: 'HMP',
        22: 'XNS-IDP',
        27: 'RDP',
        41: 'IPv6',
        43: 'IPv6-Route',
        44: 'IPv6-Frag',
        60: 'IPv6-Opts',
        66: 'RVD',
        1701: 'L2TP'
    };
    return protocols[protoNum] || protoNum;
}