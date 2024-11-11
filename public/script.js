// Alert button functionality
document.getElementById('alertButton').addEventListener('click', () => {
    alert('Button clicked!');
    });
    // Fetch data from the server
    fetch('/api/data')
    .then((response) => response.json())
    .then((data) => {
    const dataDiv = document.getElementById('dataDisplay');
    dataDiv.innerHTML = `
    <h2>Data from Server:</h2>
    <p>Message: ${data.message}</p>
    
    <p>Timestamp: ${data.timestamp}</p>
    `;
    })
    .catch((error) => console.error('Error fetching data:', error));
    // Fetch random string from the server
    fetch('/api/random-string')
    .then((response) => response.json())
    .then((data) => {
    const randomStringDiv = document.getElementById('randomStringDisplay');
    randomStringDiv.innerHTML = `
    <h2>Random String from Server:</h2>
    <p>Random String: ${data.randomString}</p>
    <p>Length: ${data.length}</p>
    `;
    })
    .catch((error) => console.error('Error fetching random string:', error));
    // Event listener for generating random string with specified length
    document.getElementById('generateStringButton').addEventListener('click', () => {
    const length = document.getElementById('stringLength').value || 10;
    fetch(`/api/random-string?length=${length}`)
    .then((response) => response.json())
    .then((data) => {
    const userRandomStringDiv = document.getElementById('userRandomStringDisplay');
    if (data.error) {
    userRandomStringDiv.innerHTML = `<p style="color:red;">Error: ${data.error}</p>`;
    } else {
    userRandomStringDiv.innerHTML = `
    <h3>Your Random String:</h3>
    <p>Random String: ${data.randomString}</p>
    <p>Length: ${data.length}</p>
    `;
    }
    })
    .catch((error) => console.error('Error fetching random string:', error));
    });

    const bcrypt = require('bcrypt');

    // Function to hash the password
    function hashPassword(password) {
        const saltRounds = 10;
        return bcrypt.hashSync(password, saltRounds);
    }
    
    app.post('/reset-password', async (req, res) => {
        const { resetKey, newPassword } = req.body;
        
        try {
            // Find user by reset key and check if the reset link has not expired
            const user = await usersCollection.findOne({
                resetKey: resetKey,
                resetExpires: { $gt: new Date() }
            });
            
            if (!user) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid or expired reset key.' 
                });
            }
    
            // Hash the new password
            const hashedPassword = hashPassword(newPassword);
            
            // Update user's password and clear reset fields
            const updateResult = await usersCollection.updateOne(
                { _id: user._id },
                {
                    $set: {
                        password: hashedPassword,
                        resetKey: null,
                        resetExpires: null
                    }
                }
            );
            
            // Check if the password update was successful
            if (updateResult.modifiedCount === 1) {
                res.json({ success: true, message: 'Your password has been successfully reset.' });
            } else {
                res.status(500).json({ success: false, message: 'Password reset failed.' });
            }
        } catch (error) {
            console.error('Error resetting password:', error);
            res.status(500).json({ success: false, message: 'Error resetting password' });
        }
    });
    