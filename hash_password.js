const bcrypt = require('bcrypt');
const saltRounds = 10;
const password = 'testpassword';
bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) console.error(err);
  else console.log('Hashed password:', hash);
});