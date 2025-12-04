// DOM Elements
      const messageInput = document.getElementById('message-input');
      const checkMessageButton = document.getElementById('check-message-btn');
      const clearButton = document.getElementById('clear-btn');
      const charCount = document.getElementById('char-count');
      const threatLevel = document.getElementById('threat-level');
      const confidenceFill = document.getElementById('confidence-fill');
      const confidenceValue = document.getElementById('confidence-value');
      const patternList = document.getElementById('pattern-list');
      const patternCount = document.getElementById('pattern-count');
      const scansContainer = document.getElementById('scans-container');
      const neuralNetwork = document.getElementById('neural-network');
      
      // Advanced spam detection patterns
      const spamPatterns = [
        {
          name: "Financial Urgency",
          regex: /(?:urgent|immediate|quick)\s*(?:money|cash|payment|transaction)/i,
          severity: "high",
          description: "Creates false urgency around financial transactions"
        },
        {
          name: "Suspicious Links",
          regex: /(?:http|https|www\.)\S*(?:bit\.ly|tinyurl|goo\.gl|shorturl)\S*/i,
          severity: "high",
          description: "Uses URL shorteners to hide malicious links"
        },
        {
          name: "Personal Information Request",
          regex: /(?:password|account|social security|credit card|banking)\s*(?:information|details|number)/i,
          severity: "high",
          description: "Attempts to extract sensitive personal information"
        },
        {
          name: "Too Good To Be True",
          regex: /(?:free|100%|guaranteed|no risk|risk-free|winner|prize|reward)\s*(?:money|cash|iphone|gift card|voucher)/i,
          severity: "medium",
          description: "Promises unrealistic rewards with no cost"
        },
        {
          name: "Authority Impersonation",
          regex: /(?:irs|government|microsoft|apple|google|amazon)\s*(?:account|suspended|verify|action required)/i,
          severity: "high",
          description: "Impersonates trusted organizations to gain credibility"
        },
        {
          name: "Grammatical Anomalies",
          regex: /(?:dear friend|kindly|revert back|congratulations|you have been selected)/i,
          severity: "medium",
          description: "Uses unusual phrasing common in scam messages"
        },
        {
          name: "Cryptocurrency Pressure",
          regex: /(?:bitcoin|crypto|ether|dogecoin)\s*(?:investment|opportunity|limited time)/i,
          severity: "medium",
          description: "Pressures quick cryptocurrency investment"
        },
        {
          name: "Lottery Scam",
          regex: /(?:lottery|raffle|sweepstakes)\s*(?:won|winner|prize|claim)/i,
          severity: "medium",
          description: "Falsely claims recipient has won a lottery"
        },
        {
          name: "Phishing Attempt",
          regex: /(?:click here|log in|verify your account|update your information)/i,
          severity: "high",
          description: "Attempts to trick user into clicking malicious links"
        },
        {
          name: "Nigerian Prince Variant",
          regex: /(?:foreign|overseas|abroad)\s*(?:businessman|prince|official)\s*(?:funds|money|inheritance)/i,
          severity: "low",
          description: "Classic advance-fee fraud scheme"
        }
      ];
      
      // Recent scans history
      let recentScans = [];
      
      // Initialize character counter
      messageInput.addEventListener('input', function() {
        const count = messageInput.value.length;
        charCount.textContent = count;
        
        // Real-time analysis when typing
        if (count > 10) {
          analyzeMessage(messageInput.value, true);
        }
      });
      
      // Initialize neural network visualization
      function initNeuralNetwork() {
        neuralNetwork.innerHTML = '';
        
        // Create neurons
        for (let i = 0; i < 12; i++) {
          const neuron = document.createElement('div');
          neuron.className = 'neuron';
          
          // Random position
          const x = Math.random() * 90 + 5;
          const y = Math.random() * 90 + 5;
          
          neuron.style.left = `${x}%`;
          neuron.style.top = `${y}%`;
          
          // Random color
          const colors = ['var(--neon-cyan)', 'var(--neon-purple)', 'var(--neon-pink)'];
          const color = colors[Math.floor(Math.random() * colors.length)];
          neuron.style.background = color;
          neuron.style.boxShadow = `0 0 10px ${color}`;
          
          neuralNetwork.appendChild(neuron);
        }
        
        // Create connections between neurons
        const neurons = document.querySelectorAll('.neuron');
        neurons.forEach((neuron, i) => {
          if (i < neurons.length - 1) {
            const nextNeuron = neurons[i + 1];
            
            const x1 = parseFloat(neuron.style.left);
            const y1 = parseFloat(neuron.style.top);
            const x2 = parseFloat(nextNeuron.style.left);
            const y2 = parseFloat(nextNeuron.style.top);
            
            // Calculate distance and angle
            const dx = x2 - x1;
            const dy = y2 - y1;
            const length = Math.sqrt(dx * dx + dy * dy) * 0.9; // 90% of window width
            const angle = Math.atan2(dy, dx) * (180 / Math.PI);
            
            const connection = document.createElement('div');
            connection.className = 'connection';
            connection.style.width = `${length}%`;
            connection.style.left = `${x1}%`;
            connection.style.top = `${y1}%`;
            connection.style.transform = `rotate(${angle}deg)`;
            
            neuralNetwork.appendChild(connection);
          }
        });
      }
      
      // Analyze message for spam patterns
      function analyzeMessage(message, isRealtime = false) {
        if (!message.trim()) {
          resetAnalysis();
          return;
        }
        
        const detectedPatterns = [];
        
        // Check message against all patterns
        spamPatterns.forEach(pattern => {
          if (pattern.regex.test(message)) {
            detectedPatterns.push({
              name: pattern.name,
              severity: pattern.severity,
              description: pattern.description
            });
          }
        });
        
        // Calculate threat level and confidence
        const threatScore = calculateThreatScore(detectedPatterns);
        const confidence = calculateConfidence(threatScore, message.length);
        const level = getThreatLevel(threatScore);
        
        // Update UI
        updateAnalysisUI(level, confidence, detectedPatterns);
        
        // Animate neural network
        animateNeuralNetwork(detectedPatterns.length);
        
        // If not realtime analysis, add to scan history
        if (!isRealtime && message.trim().length > 0) {
          addToScanHistory(message, level, detectedPatterns.length);
        }
      }
      
      // Calculate threat score based on detected patterns
      function calculateThreatScore(patterns) {
        let score = 0;
        
        patterns.forEach(pattern => {
          switch(pattern.severity) {
            case 'high': score += 3; break;
            case 'medium': score += 2; break;
            case 'low': score += 1; break;
          }
        });
        
        // Cap score at 10
        return Math.min(score, 10);
      }
      
      // Calculate confidence percentage
      function calculateConfidence(threatScore, messageLength) {
        let confidence;
        
        if (threatScore === 0) {
          // For safe messages, confidence is high if message is long enough
          confidence = messageLength > 30 ? 85 : 70;
        } else {
          // For threats, confidence increases with threat score
          confidence = 60 + (threatScore * 4);
          
          // Longer messages give more confidence in analysis
          if (messageLength > 100) {
            confidence = Math.min(confidence + 15, 98);
          }
        }
        
        // Ensure confidence stays within bounds
        return Math.min(Math.max(confidence, 30), 98);
      }
      
      // Determine threat level based on score
      function getThreatLevel(score) {
        if (score === 0) return { text: "Secure", class: "threat-low" };
        if (score <= 3) return { text: "Low Risk", class: "threat-low" };
        if (score <= 6) return { text: "Suspicious", class: "threat-medium" };
        return { text: "High Threat", class: "threat-high" };
      }
      
      // Update analysis UI
      function updateAnalysisUI(level, confidence, patterns) {
        // Update threat level
        threatLevel.textContent = level.text;
        threatLevel.className = `threat-level ${level.class}`;
        
        // Update confidence with smooth animation
        const roundedConfidence = Math.round(confidence);
        confidenceValue.textContent = `${roundedConfidence}%`;
        
        // Update confidence bar color based on threat level
        let fillColor;
        if (level.class === "threat-low") {
          fillColor = "var(--cyber-green)";
        } else if (level.class === "threat-medium") {
          fillColor = "var(--cyber-yellow)";
        } else {
          fillColor = "var(--neon-pink)";
        }
        
        // Apply the fill with animation
        confidenceFill.style.width = `${confidence}%`;
        confidenceFill.style.background = fillColor;
        confidenceFill.style.color = fillColor;
        
        // Add glow effect for high confidence
        if (confidence > 80) {
          confidenceFill.classList.add('glow');
        } else {
          confidenceFill.classList.remove('glow');
        }
        
        // Update detected patterns list
        patternList.innerHTML = '';
        
        if (patterns.length === 0) {
          const item = document.createElement('li');
          item.className = 'pattern-item';
          item.innerHTML = `
            <span class="pattern-name">No threats detected</span>
            <span class="pattern-severity severity-low">Safe</span>
          `;
          patternList.appendChild(item);
        } else {
          patterns.forEach(pattern => {
            const item = document.createElement('li');
            item.className = 'pattern-item';
            item.innerHTML = `
              <span class="pattern-name">${pattern.name}</span>
              <span class="pattern-severity severity-${pattern.severity}">${pattern.severity.toUpperCase()}</span>
            `;
            patternList.appendChild(item);
          });
        }
        
        // Update pattern count
        const patternText = patterns.length === 1 ? 'pattern' : 'patterns';
        patternCount.textContent = `${patterns.length} threat ${patternText} identified`;
      }
      
      // Reset analysis to default state
      function resetAnalysis() {
        threatLevel.textContent = "Neutral";
        threatLevel.className = "threat-level";
        
        // Reset confidence to 50%
        confidenceFill.style.width = "50%";
        confidenceFill.style.background = "var(--neon-cyan)";
        confidenceFill.style.color = "var(--neon-cyan)";
        confidenceValue.textContent = "50%";
        confidenceFill.classList.remove('glow');
        
        patternList.innerHTML = `
          <li class="pattern-item">
            <span class="pattern-name">No threats detected</span>
            <span class="pattern-severity severity-low">Safe</span>
          </li>
        `;
        
        patternCount.textContent = "0 threat patterns identified";
        
        // Reset neural network animation
        const neurons = document.querySelectorAll('.neuron');
        neurons.forEach(neuron => {
          neuron.style.animation = 'none';
          setTimeout(() => {
            neuron.style.animation = '';
          }, 10);
        });
      }
      
      // Animate neural network based on threat detection
      function animateNeuralNetwork(threatCount) {
        const neurons = document.querySelectorAll('.neuron');
        const connections = document.querySelectorAll('.connection');
        
        // Reset all animations
        neurons.forEach(neuron => {
          neuron.style.animation = 'none';
        });
        
        connections.forEach(connection => {
          connection.style.animation = 'none';
        });
        
        // Trigger animation based on threat count
        setTimeout(() => {
          neurons.forEach((neuron, i) => {
            // Stagger the animation
            const delay = i * 0.1;
            neuron.style.animation = `pulse 0.5s ${delay}s ${threatCount} alternate`;
          });
          
          connections.forEach((connection, i) => {
            // Pulsing effect on connections
            const delay = i * 0.05;
            connection.style.animation = `pulse 0.3s ${delay}s ${threatCount * 2} alternate`;
          });
        }, 100);
      }
      
      // Add scan to history
      function addToScanHistory(message, level, patternCount) {
        const scan = {
          message: message.length > 100 ? message.substring(0, 100) + "..." : message,
          level: level,
          patternCount: patternCount,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        
        recentScans.unshift(scan);
        
        // Keep only last 5 scans
        if (recentScans.length > 5) {
          recentScans.pop();
        }
        
        updateScanHistoryUI();
      }
      
      // Update scan history UI
      function updateScanHistoryUI() {
        scansContainer.innerHTML = '';
        
        recentScans.forEach(scan => {
          const scanItem = document.createElement('div');
          scanItem.className = 'scan-item';
          
          let statusColor = "var(--cyber-green)";
          if (scan.level.class === "threat-medium") statusColor = "var(--cyber-yellow)";
          if (scan.level.class === "threat-high") statusColor = "var(--neon-pink)";
          
          scanItem.innerHTML = `
            <div class="scan-message">${scan.message}</div>
            <div class="scan-result">
              <span class="scan-status" style="color: ${statusColor}">${scan.level.text}</span>
              <span class="scan-time">${scan.time}</span>
            </div>
          `;
          
          scansContainer.appendChild(scanItem);
        });
        
        // Add placeholder if no scans
        if (recentScans.length === 0) {
          const placeholder = document.createElement('div');
          placeholder.className = 'scan-item';
          placeholder.innerHTML = `
            <div class="scan-message">No scans performed yet. Enter a message to begin analysis.</div>
            <div class="scan-result">
              <span class="scan-status" style="color: var(--cyber-green)">Ready</span>
              <span class="scan-time">--:--</span>
            </div>
          `;
          scansContainer.appendChild(placeholder);
        }
      }
      
      // Create visual effect when scanning
      function createScanEffect() {
        const effect = document.createElement('div');
        effect.className = 'pulse-ring';
        effect.style.left = `${Math.random() * 80 + 10}%`;
        effect.style.top = `${Math.random() * 80 + 10}%`;
        
        document.body.appendChild(effect);
        
        // Remove after animation completes
        setTimeout(() => {
          effect.remove();
        }, 2000);
      }
      
      // Event Listeners
      checkMessageButton.addEventListener('click', () => {
        const message = messageInput.value.trim();
        
        if (!message) {
          // Show warning effect
          threatLevel.textContent = "No Input";
          threatLevel.className = "threat-level threat-medium";
          confidenceFill.style.width = "10%";
          confidenceFill.style.background = "var(--cyber-yellow)";
          confidenceValue.textContent = "10%";
          
          patternList.innerHTML = `
            <li class="pattern-item">
              <span class="pattern-name">No message to analyze</span>
              <span class="pattern-severity severity-medium">Warning</span>
            </li>
          `;
          
          patternCount.textContent = "Please enter a message to analyze";
          
          // Animate neural network with warning
          animateNeuralNetwork(1);
          return;
        }
        
        // Create scanning effect
        createScanEffect();
        
        // Add scanning text temporarily
        const originalText = checkMessageButton.innerHTML;
        checkMessageButton.innerHTML = '<i class="fas fa-cog fa-spin"></i> Scanning...';
        checkMessageButton.disabled = true;
        
        // Simulate AI processing delay
        setTimeout(() => {
          analyzeMessage(message, false);
          checkMessageButton.innerHTML = originalText;
          checkMessageButton.disabled = false;
        }, 800);
      });
      
      clearButton.addEventListener('click', () => {
        messageInput.value = '';
        charCount.textContent = '0';
        resetAnalysis();
      });
      
      // Initialize the application
      function init() {
        initNeuralNetwork();
        updateScanHistoryUI();
        
        // Initialize confidence bar
        confidenceFill.style.width = "50%";
        confidenceFill.style.background = "var(--neon-cyan)";
        confidenceFill.style.color = "var(--neon-cyan)";
        
        // Add initial scan to history
        addToScanHistory("System initialized. Ready for threat analysis.", { text: "Secure", class: "threat-low" }, 0);
        
        // Add some sample scans for demo
        setTimeout(() => {
          addToScanHistory("Congratulations! You've won a $1000 Amazon gift card. Click here to claim your prize.", { text: "High Threat", class: "threat-high" }, 3);
          addToScanHistory("Your Microsoft account has been suspended. Please verify your information immediately.", { text: "Suspicious", class: "threat-medium" }, 2);
        }, 1000);
      }
      
      // Initialize when page loads
      window.addEventListener('DOMContentLoaded', init);