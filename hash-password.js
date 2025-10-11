const bcrypt = require('bcrypt');

async function hashPassword(password) {
    const hash = await bcrypt.hash(password, 10);
    console.log(hash);
}

hashPassword('SecurePass123!').catch(console.error);