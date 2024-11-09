const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');

registerBtn.addEventListener('click', () => container.classList.add("active"));
loginBtn.addEventListener('click', () => container.classList.remove("active"));

let selectedOrder = [];

const AES_SECRET_KEY = "MySecretKey";

function resetPasswordOrder() {
    selectedOrder = [];
    document.querySelectorAll('.passimg').forEach(img => img.classList.remove('selected'));
}

function inimg(image) {
    const imageId = image.id;
    if (!image.classList.contains('selected')) {
        selectedOrder.push(imageId);
        image.classList.add('selected');
    } else {
        selectedOrder = selectedOrder.filter(id => id !== imageId);
        image.classList.remove('selected');
    }
}
function generateSalt(length = 16) {
    return CryptoJS.lib.WordArray.random(length).toString();
}
function encryptPassword(order,salt) {
    const hashedPassword = CryptoJS.SHA256(order.join(",")+salt).toString();
    return CryptoJS.AES.encrypt(hashedPassword, AES_SECRET_KEY).toString();
}

function decryptAndCompare(encryptedPassword, order,storedsalt) {
    const hashedPassword = CryptoJS.SHA256(order.join(",")+storedsalt).toString();
    const decryptedPassword = CryptoJS.AES.decrypt(encryptedPassword, AES_SECRET_KEY).toString(CryptoJS.enc.Utf8);
    return hashedPassword === decryptedPassword;
}

document.getElementById('signupform').addEventListener('submit', function(event) {
    event.preventDefault();

    const nameInput = document.getElementById('nameinput').value.trim();
    const emailInput = document.getElementById('emailinputsignup').value.trim();
    const passwordOrder = selectedOrder;

    if (nameInput === "" || emailInput === "" || passwordOrder.length === 0) {
        alert("Please complete all fields.");
        return;
    }

    const users = JSON.parse(localStorage.getItem('users')) || [];
    const salt = generateSalt();
    const hashedencryptedPassword = encryptPassword(passwordOrder,salt);
    const userExists = users.some(user => user.email === emailInput);

    if (userExists) {
        alert("An account with this email already exists.");
    } else {
        users.push({ name: nameInput, email: emailInput, hashedencryptedPassword,salt});
        localStorage.setItem('users', JSON.stringify(users));
        
        alert("Account created successfully! You can now log in.");
        
        event.target.reset();
        resetPasswordOrder();
        setTimeout(() => container.classList.remove("active"), 1000);
    }
});

document.getElementById('signInForm').addEventListener('submit', function(event) {
    event.preventDefault();

    const emailInput = document.getElementById('emailInput').value.trim();
    const passwordOrder = selectedOrder;

    if (emailInput === "" || passwordOrder.length === 0) {
        alert("Please enter both email and password.");
        return;
    }

    const users = JSON.parse(localStorage.getItem('users')) || [];
    const matchingUser = users.find(user => user.email === emailInput);

    if (matchingUser && decryptAndCompare(matchingUser.hashedencryptedPassword, passwordOrder,matchingUser.salt)) {
        alert(`Login successful! Welcome, ${matchingUser.name}.`);
        NewTab();
    } else {
        alert("Invalid email or password. Please try again.");
    }

    resetPasswordOrder();
});
function NewTab(){
    window.location.href="home.html";
}