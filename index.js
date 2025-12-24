const conn = require('./connection');
const express = require('express');
const session = require('express-session');
const bodyParser = require("body-parser");
const e = require('express');
const app = express();
const mongoose = require("mongoose");
const User = require("./models/user");
const SubscriptionPlan = require("./models/subplan");
const BusinessCard = require("./models/bcard");
const cardt = require("./models/card");
const temp = require("./models/templates");
const cpages = require("./models/custompages");
const mcompany = require("./models/company");
const emp = require("./models/employee");
const bcrypt = require("bcrypt");
const path = require('path');
const adminModel = require('./models/admin');
const multer = require('multer');
const Image = require('./models/image');
const LogModel = require('./models/logModel');
const { ObjectId } = require('mongodb');
const AWS = require('aws-sdk');
const dotenv = require('dotenv');
const os = require('os');

// Slugify helper function
const slugify = (text) => {
  if (!text) return '';
  return text.toString().toLowerCase().trim()
    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // Remove accents
    .replace(/đ/g, 'd') // Convert Vietnamese đ
    .replace(/Đ/g, 'd')
    .replace(/\s+/g, '') // Remove spaces
    .replace(/[^\w-]+/g, '') // Remove non-word chars
    .replace(/--+/g, '-');
};

dotenv.config();

app.set("views", __dirname + "/views");
app.set("view engine", "ejs");

app.use(express.static(__dirname + "/public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


app.use('/public', express.static(__dirname + "/public"));

const fs = require('fs');
const defaultSessionSecret = 'mydefaultsecretkey';

app.use(session({
  secret: defaultSessionSecret,
  resave: false,
  saveUninitialized: true
}));

// Middleware to detect Local IP for QR Code access from mobile
app.use((req, res, next) => {
  const interfaces = os.networkInterfaces();
  let localIp = 'localhost';
  let candidateIps = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        candidateIps.push(iface.address);
      }
    }
  }

  // Filter out IPs likely to be gateways or virtual host adapters (often ending in .1)
  // But keep them if we have no other choice.
  // We want to find the "real" LAN IP (e.g., 192.168.4.76).
  const nonVirtualIps = candidateIps.filter(ip => !ip.endsWith('.1'));
  const targetPool = nonVirtualIps.length > 0 ? nonVirtualIps : candidateIps;

  // Prioritize 192.168.x.x, then 10.x.x.x, then others
  const preferredIp = targetPool.find(ip => ip.startsWith('192.168.'))
    || targetPool.find(ip => ip.startsWith('10.'))
    || targetPool[0];

  if (preferredIp) {
    localIp = preferredIp;
  }

  res.locals.serverIp = localIp;
  next();
});

AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const s3 = new AWS.S3();

// Reusable upload function with S3 local fallback
const smartUpload = async (file, folder, filenamePrefix) => {
  if (!file) return null;
  const extension = file.originalname.split('.').pop();
  const filename = `${Date.now()}_${filenamePrefix}.${extension}`;

  try {
    // Try S3 first
    if (process.env.S3_BUCKET_NAME && process.env.AWS_ACCESS_KEY_ID) {
      const s3Params = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: `${folder}/${filename}`,
        Body: file.buffer,
        ContentType: file.mimetype,
      };
      const s3UploadResponse = await s3.upload(s3Params).promise();
      return s3UploadResponse.Location;
    }

    // Local fallback
    const uploadDir = path.join(__dirname, 'public', 'uploads', folder);
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    const filePath = path.join(uploadDir, filename);
    fs.writeFileSync(filePath, file.buffer);
    return `/public/uploads/${folder}/${filename}`;
  } catch (err) {
    console.error("Upload Error:", err.message);
    return null;
  }
};

// Middleware toàn cục để đưa thông tin user và công ty vào mọi giao diện (EJS)
app.use(async (req, res, next) => {
  res.locals.loggedInUserCompany = null;
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId);

      if (user && user.username === 'huynx') {
        user.role = 'admin';
        // Ta không cần await user.save() ở đây mỗi lần, 
        // chỉ cần set trong memory để vượt qua check isAdmin
      }

      res.locals.loggedInUser = user;

      if (user && user.companyId) {
        const company = await mcompany.findById(user.companyId);
        res.locals.loggedInUserCompany = company || null;
      }
    } catch (err) {
      console.error("Session User Error:", err);
      res.locals.loggedInUser = null;
      res.locals.loggedInUserCompany = null;
    }
  } else {
    res.locals.loggedInUser = null;
  }
  next();
});

// Middleware kiểm tra quyền Quản trị (Admin, CEO, hoặc Employee)
const isAdmin = (req, res, next) => {
  if (res.locals.loggedInUser && (
    res.locals.loggedInUser.role === 'admin' ||
    res.locals.loggedInUser.role === 'ceo' ||
    res.locals.loggedInUser.role === 'employee' ||
    res.locals.loggedInUser.username === 'huynx'
  )) {
    return next();
  }
  res.status(403).send(`
    <div style="text-align:center; padding:50px; font-family:sans-serif;">
      <h1 style="color:red;">⛔ TRUY CẬP BỊ TỪ CHỐI</h1>
      <p>Bạn không có quyền truy cập vào khu vực này.</p>
      <a href="/">Quay về trang chủ</a>
    </div>
  `);
};


const storage = multer.memoryStorage();
const upload = multer({ storage: storage });


app.get('/', function (req, res) {
  res.render('landing/index');
});


app.get('/login', async (req, res) => {
  res.render('login/login');
});

app.get('/register', async (req, res) => {
  res.render('admin/register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password, number } = req.body;

    // Validate email domain - only allow @at-energy.vn
    if (!email.endsWith('@at-energy.vn')) {
      return res.status(400).send("Chỉ chấp nhận email có đuôi @at-energy.vn. Vui lòng sử dụng email công ty.");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      number
    });
    await newUser.save();
    req.session.userId = newUser._id;
    res.redirect('/create-card');
  } catch (error) {
    console.error(error);
    res.status(500).send("Error during registration");
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Try to find user by username first, then by email
    let user = await User.findOne({ username });

    // If not found by username, try with @at-energy.vn email
    if (!user) {
      const emailToCheck = username.includes('@') ? username : `${username}@at-energy.vn`;
      user = await User.findOne({ email: emailToCheck });
    }

    if (user && await bcrypt.compare(password, user.password)) {
      req.session.userId = user._id;

      // Redirect based on role
        if (user.role === 'admin' || user.username === 'huynx') {
          return res.redirect('/user');
        } else if (user.role === 'ceo') {
          return res.redirect('/employee-list');
        } else if (user.role === 'employee') {
          return res.redirect('/index');
        }

        res.redirect('/create-card');
      } else {
      res.status(401).send("Tên đăng nhập hoặc mật khẩu không đúng");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/about', function (req, res) {
  res.render('about/about');
});

app.get('/contact', function (req, res) {
  res.render('contact/contact');
});

app.get('/create-card', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const templates = await temp.find();
    res.render('user/select-template', { templates });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.post('/design-card', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  try {
    const { templateId } = req.body;
    const template = await temp.findById(templateId);
    const user = await User.findById(req.session.userId);

    // Kiểm tra xem user đã có card nào chưa để lấy lại data cũ
    let selectedItem = await BusinessCard.findOne({ user: req.session.userId }).lean();

    if (!selectedItem) {
      selectedItem = {
        template: templateId,
        cardType: template.cardType,
        subscriptionPlan: user.selectedItems.length > 0 ? user.selectedItems[0].subscriptionPlan : { plan: null }
      };
    }

    res.render('user/designer', { user, template, selectedItem });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get('/my-card', async (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  try {
    let template = await temp.findOne({ name: 'profsample-1' });
    if (!template) {
      // Nếu có Professional-1 thì sửa tên, nếu không có gì thì tạo mới
      template = await temp.findOne({ name: 'Professional-1' });
      if (template) {
        template.name = 'profsample-1';
        await template.save();
      } else {
        template = new temp({ name: 'profsample-1', cardType: new mongoose.Types.ObjectId() });
        await template.save();
      }
    }
    const user = await User.findById(req.session.userId);

    // Tìm card cũ của user để điền lại thông tin vào form
    let selectedItem = await BusinessCard.findOne({ user: req.session.userId }).lean();

    // Nếu chưa có card nào, tạo cấu hình mặc định
    if (!selectedItem) {
      selectedItem = { template: template._id };
    }

    res.render('user/designer', { user, template, selectedItem });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// Route cho người lạ xem card
app.get('/card/:username', async (req, res) => {
  try {
    const slugParam = req.params.username;
    let user = await User.findOne({ username: slugParam });
    let employeeRecord = null;

    if (user) {
      if (user.employeeId) {
        employeeRecord = await emp.findById(user.employeeId);
      }
      if (!employeeRecord) {
        employeeRecord = await emp.findOne({ email: user.email });
      }
    }

    if (!user) {
      employeeRecord = await findEmployeeBySlug(slugParam);
      if (employeeRecord) {
        user = await User.findOne({ employeeId: employeeRecord._id });
      }
    }

    if (!user) {
      return res.status(404).send("User not found");
    }

    const bcard = await BusinessCard.findOneAndUpdate(
      { user: user._id },
      {
        $inc: { viewCount: 1 },
        $set: { lastViewedAt: new Date() }
      },
      { new: true, sort: { _id: -1 } }
    );
    if (!bcard) return res.status(404).send("This user hasn't finished their card yet");

    let companyData = null;
    if (user.companyId) {
      companyData = await mcompany.findById(user.companyId);
    }
    if (!companyData && employeeRecord && employeeRecord.company) {
      companyData = await mcompany.findById(employeeRecord.company);
    }

    const fallbackSocialLinks = [];
    ['facebook', 'linkedin', 'zalo', 'tiktok'].forEach(platform => {
      const url = employeeRecord ? employeeRecord[platform] : '';
      if (url) {
        fallbackSocialLinks.push({ platform, url });
      }
    });

    const socialLinks = (employeeRecord && employeeRecord.socialLinks && employeeRecord.socialLinks.length)
      ? employeeRecord.socialLinks
      : fallbackSocialLinks;

    const cardSlug = employeeRecord
      ? (employeeRecord.slug || slugify(employeeRecord.name))
      : slugify(user.username);

    // Sử dụng giao diện xem công khai chuyên nghiệp đã tạo
    res.render('user/public-card', { user, bcard, companyData, socialLinks, cardSlug });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error loading card");
  }
});


// Short URL for cards - redirects to full card URL
app.get('/c/:username', (req, res) => {
  res.redirect(`/card/${req.params.username}`);
});


app.listen(3000, function () {
  console.log('Server started at port 3000');
})

// ============ TEMPLATE MANAGEMENT ROUTES ============

// Add new template (Admin only)
app.post('/add-template', isAdmin, upload.single('templateImage'), async (req, res) => {
  try {
    const { name, description } = req.body;

    // Tạo một cardType mặc định nếu chưa có
    let defaultCardType = await cardt.findOne();
    if (!defaultCardType) {
      defaultCardType = new cardt({ name: 'Business Card' });
      await defaultCardType.save();
    }

    const newTemplate = new temp({
      name: name || 'New Template',
      cardType: defaultCardType._id,
      fields: [
        { name: 'Name', type: 'text' },
        { name: 'Role', type: 'text' },
        { name: 'Email', type: 'email' },
        { name: 'Phone', type: 'text' },
        { name: 'Address', type: 'text' },
        { name: 'Company', type: 'text' },
        { name: 'Website', type: 'text' }
      ]
    });

    // Nếu có upload hình ảnh
    if (req.file) {
      newTemplate.img = {
        data: req.file.buffer,
        contentType: req.file.mimetype
      };
    }

    await newTemplate.save();
    res.redirect('/create-card');
  } catch (error) {
    console.error('Error adding template:', error);
    res.status(500).send('Lỗi khi tạo mẫu mới');
  }
});

// Edit/Rename template (Admin only)
app.post('/edit-template', isAdmin, async (req, res) => {
  try {
    const { templateId, name } = req.body;

    await temp.findByIdAndUpdate(templateId, { name });

    res.redirect('/create-card');
  } catch (error) {
    console.error('Error editing template:', error);
    res.status(500).send('Lỗi khi chỉnh sửa mẫu');
  }
});

// ============ END TEMPLATE MANAGEMENT ============




// Log Model
const logModel = new LogModel();

// Middleware for logging route access
app.use(async (req, res, next) => {
  const routeAccessDetails = {
    method: req.method,
    path: req.path,
    query: req.query,
    params: req.params,
  };

  await logModel.logEvent('route_access', routeAccessDetails);
  next();
});



// Displaying all the logs
app.get('/_logs', async (req, res) => {
  try {
    const logs = await logModel.getAllLogs();
    console.log(logs);
    res.json(logs);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/admin', isAdmin, async (req, res) => {
  try {
    const admin = await adminModel.findOne({ username: 'admins', password: 'admin' });

    if (admin) {
      // If the admin credentials are found, render the admin dashboard using EJS
      res.render('admin/index');
    } else {
      // If admin credentials are not found, serve the login page from the admin folder using EJS
      res.render('admin/login');
    }
  } catch (error) {
    // Handle any errors, e.g., display an error page or redirect to login
    console.error(error);
    res.redirect('/');
  }
});


app.post('/admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await adminModel.findOne({ username });
    if (!user) {
      res.send("User does not exist");
    } else if (password === user.password) {
      res.render('admin/index');
    } else {
      res.send("Invalid password");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get('/index', isAdmin, async (req, res) => {
  if (res.locals.loggedInUser && res.locals.loggedInUser.role === 'employee') {
    return res.redirect('/employee-list');
  }

  try {
    // Fetch real data for dashboard
    const userCount = await User.countDocuments();
    const templateCount = await temp.countDocuments();
    const cardCount = await BusinessCard.countDocuments();
    const companyCount = await mcompany.countDocuments();

    // Get recent users (last 5)
    const recentUsers = await User.find()
      .sort({ _id: -1 })
      .limit(5)
      .select('username email number createdAt');

    res.render('admin/index', {
      stats: {
        users: userCount,
        templates: templateCount,
        cards: cardCount,
        companies: companyCount
      },
      recentUsers
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.render('admin/index', {
      stats: { users: 0, templates: 0, cards: 0, companies: 0 },
      recentUsers: []
    });
  }
});


app.get('/subscription', isAdmin, async (req, res) => {

  const subscriptionPlans = await SubscriptionPlan.find();
  res.render('admin/subscription', { subscriptionPlans });
});


app.post('/subscription', async (req, res) => {
  try {
    const { name, price, duration } = req.body;

    const subscriptionPlan = new Subplan1({ name, price, duration });
    await subscriptionPlan.save();

    res.redirect('/subscription');
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.post('/edit-subscription', async (req, res) => {
  try {
    const { name, price, duration } = req.body;

    await SubscriptionPlan.findByIdAndUpdate(req.params.id, { name, price, duration });

    res.redirect('/subscription');
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// getting subscription details 

app.get('/add-subscription', isAdmin, async (req, res) => {
  try {
    res.render('admin/add-subscription');
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

//add subscription plan

app.post('/add-subscription', async (req, res) => {
  try {
    const { name, price, featureNames } = req.body;


    if (!name || !price || !featureNames || !Array.isArray(featureNames)) {
      return res.status(400).json({ error: 'Invalid data format' });
    }


    const newSubscriptionPlan = new SubscriptionPlan({
      name,
      price,
      features: featureNames,
    });


    await newSubscriptionPlan.save();

    const subscriptionPlans = await SubscriptionPlan.find();
    res.render('admin/subscription', { subscriptionPlans });
  } catch (error) {
    console.error('Error adding subscription plan:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




app.get('/edit-subscription/:id', async (req, res) => {
  try {
    const plan = await SubscriptionPlan.findById(req.params.id);
    if (!plan) {
      return res.status(404).send('Subscription plan not found');
    }
    res.render('admin/edit-subscription', { plan });
  } catch (error) {
    console.error('Error fetching subscription plan:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/edit-subscription/:id', async (req, res) => {
  const planId = req.params.id;

  try {

    const existingPlan = await SubscriptionPlan.findById(planId);

    if (!existingPlan) {
      return res.status(404).json({ error: 'Subscription plan not found' });
    }


    const { name, price, existingFeatures } = req.body;


    const updatedFeatures = existingFeatures.split(',');


    existingPlan.name = name;
    existingPlan.price = price;
    existingPlan.features = updatedFeatures;


    await existingPlan.save();
    const subscriptionPlans = await SubscriptionPlan.find();
    res.render('admin/subscription', { subscriptionPlans });
  } catch (error) {
    console.error('Error updating subscription plan:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/add-user', isAdmin, async (req, res) => {
  try {
    // Fetch subscription plans, card types, and templates from the database
    const subscriptionPlans = await SubscriptionPlan.find();
    const cardTypes = await cardt.find();
    const templates = await temp.find();

    res.render('admin/add-user', { subscriptionPlans, cardTypes, templates });
  } catch (error) {
    console.error('Error fetching data for user form:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/add-card', async (req, res) => {

  const mobileNumber = req.body.phoneNumber; // Get the entered mobile number

  try {
    // Check if the user already exists based on the mobile number
    const existingUser = await User.findOne({ number: mobileNumber });
    console.log(existingUser);
    if (existingUser) {
      // If the user exists, you can redirect to the add-card page or perform necessary actions
      const subscriptionPlans = await SubscriptionPlan.find();
      const cardTypes = await cardt.find();
      const templates = await temp.find();

      res.render('admin/add-card', { existingUser, subscriptionPlans, cardTypes, templates });
      // Redirect to the add-card page with the user ID
    } else {
      // If the user doesn't exist, you can handle it as needed, such as displaying an error message
      res.send('User not found. Please register.');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/update-cards', async (req, res) => {
  const { username, email, number, subscriptionPlan, occassion, cardType, template } = req.body
  console.log(req.body);
  try {
    // Find the user by mobile number
    const user = await User.findOne({ number: number });

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Push the new card details and subscription plan to the user's selectedItems array
    const newSelectedItem = {
      occasion: occassion,
      cardType: cardType,
      template: template,
      subscriptionPlan: {
        plan: subscriptionPlan,
      },
      // Add other necessary fields for the new item
    };

    // Push the new item to the selectedItems array
    user.selectedItems.push(newSelectedItem);

    // Save the updated user object
    await user.save();
    const users1 = await fetchUserData();
    res.render('admin/user', { users1 });

  } catch (error) {
    console.error('Error adding card:', error);
    return res.status(500).send('Internal Server Error');
  }
});

app.get('/user-details', async (req, res) => {
  try {
    // Your logic for fetching subscription plan data if needed
    // const subscriptionPlan = await Subplan1.findById(req.params.id);

    res.render('admin/user-details');
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


const fetchUserData = async () => {
  try {
    const users = await User.find()
      .populate({
        path: 'selectedItems.subscriptionPlan.plan',
        model: 'SubscriptionPlan',
        select: 'name',
      })
      .populate({
        path: 'selectedItems.cardType',
        model: 'CardType',
        select: 'name',
      })
      .populate({
        path: 'selectedItems.template',
        model: 'Template',
        select: 'name',
      });
    return users;
  } catch (error) {
    throw error;
  }
};

app.get('/user', isAdmin, async (req, res) => {
  try {
    const users1 = await fetchUserData();
    res.render('admin/user', { users1 });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.get('/get-cards/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId)
      .populate({
        path: 'selectedItems.subscriptionPlan.plan',
        model: 'SubscriptionPlan',
        select: 'name',
      })
      .populate({
        path: 'selectedItems.cardType',
        model: 'CardType',
        select: 'name',
      });

    console.log(user);
    res.json({ cards: user.selectedItems });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//card deletion code
app.post('/delete-card/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const cardId = req.body.cardId;
    const businessCard = await BusinessCard.findByIdAndDelete(cardId);

    if (businessCard) {
      const s3 = new AWS.S3();

      const deleteObject = async (objectKey) => {
        const decodedObjectKey = decodeURIComponent(objectKey);
        const key1 = decodedObjectKey.split('.com/')[1];
        const params = {
          Bucket: process.env.S3_BUCKET_NAME,
          Key: key1, // Specify the folder path
        };

        try {
          await s3.deleteObject(params).promise();
          console.log(`Object deleted successfully: ${key1}`);
        } catch (error) {
          console.error(`Error deleting object: ${key1}`, error);
          throw error;
        }
      };

      await deleteObject(businessCard.Image);
      await deleteObject(businessCard.bgImg);
    }
    await User.findByIdAndUpdate(userId, {
      $pull: { selectedItems: { _id: cardId } }
    });

    const users1 = await fetchUserData();
    res.render('admin/user', { users1 }); // Redirect to home or any desired route
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/user-grid', async (req, res) => {
  try {
    // Your logic for fetching subscription plan data if needed
    // const subscriptionPlan = await Subplan1.findById(req.params.id);

    res.render('admin/user-grid');
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.get("/delete/:id", async (req, res) => {
  let planid = req.params.id;
  try {

    if (!ObjectId.isValid(planid)) {
      return res.status(400).json({ error: 'Invalid ObjectId' });
    }


    const deletedPlan = await SubscriptionPlan.findByIdAndDelete(planid);
    const subscriptionPlans = await SubscriptionPlan.find();

    if (!deletedPlan) {
      return res.status(404).json({ error: 'Subscription plan not found' });
    }

    res.render('admin/subscription', { subscriptionPlans });
  } catch (error) {
    console.error('Error deleting subscription plan:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }


});



// app.post('/add-user', async (req, res) => {
//     try {
//         const { username, email, number, subscriptionPlan, occasion, cardType, template } = req.body;
//         console.log(req.body);

//         // Create a new user
//         const Plan = new ObjectId(subscriptionPlan);
//         const card = new ObjectId(cardType);
//         const temp = new ObjectId(template);

//         const newUser = new User({
//             username,
//             email,
//             number,
//             selectedItems: [
//                 {
//                     occasion,
//                     cardType: card,
//                     template: temp,
//                     subscriptionPlan: {
//                         plan: Plan,
//                     },
//                 },
//             ],
//         });

//         // Save the user to the database
//         const savedUser = await newUser.save();

//         // Redirect to the edit page for the newly created user
//         res.redirect(`/template1?userId=${savedUser._id}`);
//     } catch (error) {
//         console.error('Error creating user:', error);
//         res.status(500).send('Internal Server Error');
//     }
// });

app.get('/imageupload', async (req, res) => {
  try {
    const data = await Image.find({});
    res.render('admin/image', { items: data });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal Server Error');
  }
});

//   app.post('/imageupload', upload.single('image'), async (req, res) => {
//     try {
//       const obj = {
//         name: req.body.name,
//         desc: req.body.desc,
//         img: {
//           data: await fs.readFileAsync(path.join(__dirname, 'uploads', req.file.filename)),
//           contentType: 'image/png',
//         },
//       };
//       await Image.create(obj);
//       res.redirect('/');
//     } catch (err) {
//       console.error(err);
//       res.status(500).send('Internal Server Error');
//     }
//   });

app.post('/add-user', async (req, res) => {
  try {
    // ... (validate and sanitize user input)

    // Extract selected values
    const subscriptionPlanId = req.body.subscriptionPlan;
    const templateId = req.body.template;
    const cardTypeId = req.body.cardType;

    // Create a new user
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      number: req.body.number,
      selectedItems: [
        {
          occasion: req.body.occassion,
          cardType: cardTypeId,
          template: templateId,
          subscriptionPlan: {
            plan: subscriptionPlanId,
            expiresAt: req.body.expiresAt,
          },
        },
      ],
    });

    // Save the user to the database
    const savedUser = await newUser.save();
    const cardId = savedUser.selectedItems[0]._id;

    // Redirect to card generation if it's the user flow
    if (req.session.userId) {
      const template = await temp.findById(templateId);
      return res.render(`admin/${template.name}`, { user: savedUser, selectedItem: savedUser.selectedItems[0] });
    }

    const users1 = await fetchUserData();
    res.render('admin/user', { users1 });
  } catch (error) {
    // Handle errors
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});




app.get('/edit-user/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const subscriptionPlans = await SubscriptionPlan.find();
    const cardTypes = await cardt.find();
    const templates = await temp.find();

    res.render('admin/edit-user', { user, subscriptionPlans, cardTypes, templates });
  } catch (error) {
    console.error('Error fetching user for editing:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/edit-user/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    // Retrieve the user by ID
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user fields
    user.username = req.body.username;
    user.email = req.body.email;
    user.number = req.body.number;

    // Clear existing selectedItems array
    user.selectedItems = [];

    // Get the number of selectedItems from the hidden field
    const selectedItemsCount = parseInt(req.body.selectedItemsCount, 10);

    // Iterate over form fields to reconstruct selectedItems array
    for (let index = 0; index < selectedItemsCount; index++) {
      user.selectedItems.push({
        occasion: req.body[`occasion_${index}`],
        cardType: new ObjectId(req.body[`cardType_${index}`]),
        template: new ObjectId(req.body[`template_${index}`]),
        subscriptionPlan: {
          plan: new ObjectId(req.body[`subscriptionPlan_${index}`]),
        },
        // Add other fields if needed
      });
    }

    // Save the updated user to the database
    const updatedUser = await user.save();

    // Redirect to the user listing page or any other page after successful update
    const users1 = await fetchUserData();
    res.render('admin/user', { users1 });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).send('Internal Server Error');
  }
});







app.get('/template1', (req, res) => {
  // Retrieve fixed values from query parameters
  const subscriptionPlanId = req.query.subscriptionPlan;
  const templateId = req.query.template;
  const cardTypeId = req.query.cardType;

  // Render the template.ejs file with fixed values
  res.render('template1', { subscriptionPlanId, templateId, cardTypeId });
});




app.post('/template1', async (req, res) => {
  try {
    const { name, email, number, subscriptionPlan, occasion, cardType, template } = req.body;
    console.log(req.body);

    // Create a new user
    const Plan = new ObjectId(subscriptionPlan);
    const card = new ObjectId(cardType);
    const temp = new ObjectId(template);

    const newBusinnessCard = new BusinessCard({
      username,
      email,
      number,
      selectedItems: [
        {
          occasion,
          cardType: card,
          template: temp,
          subscriptionPlan: {
            plan: Plan,
          },
        },
      ],
    });

    // Save the user to the database
    const savedUser = await newUser.save();

    // Redirect to the edit page for the newly created user
    res.redirect(`/template1?userId=${savedUser._id}`);
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).send('Internal Server Error');
  }
}
);

app.post('/generate-card/:userid', async (req, res) => {
  try {
    const cardId = req.body.cardId;
    const userId = req.params.userid;


    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Find the selected item with the given cardId
    const selectedItem = user.selectedItems.find(item => item._id.toString() === cardId);

    if (!selectedItem) {
      return res.status(404).json({ error: 'Selected item not found' });
    }

    const template = await temp.findById(selectedItem.template);


    if (!template) {
      return res.status(404).json({ error: 'Template not found' });
    }
    const templateName = template.name;
    res.render(`admin/${templateName}`, { user, selectedItem });

  } catch (error) {
    console.error('Error generating card:', error);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/cardlist', async (req, res) => {
  try {
    const users1 = await fetchUserData();
    res.render('admin/cardlist', { users1 });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});


app.post('/businesscard/:userId', upload.fields([
  { name: 'Image', maxCount: 1 },
  { name: 'bgImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const userId = req.params.userId;
    const selectedItems = req.body.selectedItems;
    const selectedItemsObject = selectedItems ? JSON.parse(selectedItems) : {};
    const businessid = selectedItemsObject._id || new mongoose.Types.ObjectId();

    const subscriptionPlan = selectedItemsObject.subscriptionPlan || {};
    const plan = subscriptionPlan.plan || null;
    const templateId = selectedItemsObject.template;
    const cardid = selectedItemsObject.cardType || null;
    const occasion = selectedItemsObject.occasion || 'General';
    const template = await temp.findById(templateId).lean() || { fields: [] };

    // Extract the files from req.files
    const images = req.files['Image'] ? req.files['Image'][0] : null;
    const bgImage = req.files['bgImage'] ? req.files['bgImage'][0] : null;

    // Thu thập toàn bộ các trường từ form designer
    const coreFields = ['Name', 'Role', 'Company', 'URL', 'Phone1', 'Phone2', 'Address', 'ContactEmail', 'VideoURL', 'ImageFit', 'ImagePos'];
    const templateFields = coreFields.map(fieldName => ({
      fieldName: fieldName,
      fieldValue: req.body[fieldName] || ''
    }));

    // Thêm các field khác nếu có định nghĩa trong template
    if (template.fields) {
      template.fields.forEach(field => {
        if (!coreFields.includes(field.name)) {
          templateFields.push({
            fieldName: field.name,
            fieldValue: req.body[field.name] || ''
          });
        }
      });
    }

    const uploadToS3 = async (file, folder, filenamePrefix) => {
      const extension = file.originalname.split('.').pop();
      const filename = `${userId}_${Date.now()}_${filenamePrefix}.${extension}`;

      try {
        // Ưu tiên S3 nếu có cấu hình
        if (process.env.S3_BUCKET_NAME && process.env.AWS_ACCESS_KEY_ID) {
          const s3Params = {
            Bucket: process.env.S3_BUCKET_NAME,
            Key: `${folder}/${filename}`,
            Body: file.buffer,
            ContentType: file.mimetype,
          };
          const s3UploadResponse = await s3.upload(s3Params).promise();
          return s3UploadResponse.Location;
        }

        // Nếu không có S3, lưu local
        const uploadDir = path.join(__dirname, 'public', 'uploads', folder);
        if (!fs.existsSync(uploadDir)) {
          fs.mkdirSync(uploadDir, { recursive: true });
        }
        const filePath = path.join(uploadDir, filename);
        fs.writeFileSync(filePath, file.buffer);
        return `/public/uploads/${folder}/${filename}`;
      } catch (err) {
        console.warn("Upload failed:", err.message);
        return null;
      }
    };

    const image1Url = images ? await uploadToS3(images, 'cards_img', 'image') : null;
    const image2Url = bgImage ? await uploadToS3(bgImage, 'cards_img', 'bgimage') : null;

    console.log(templateFields);

    const filter = {
      user: userId,
      _id: businessid
    };

    const update = {
      user: userId,
      selectedCardType: cardid,
      selectedTemplate: templateId,
      selectedSubscriptionPlan: plan,
      templateFields: templateFields,
      bgColor: req.body.bgColor || '',
      // Social Media Links
      socialLinks: {
        facebook: req.body.facebook || '',
        linkedin: req.body.linkedin || '',
        zalo: req.body.zalo || '',
        tiktok: req.body.tiktok || '',
      },
    };

    // Chỉ cập nhật ảnh nếu có ảnh mới hoặc giữ lại ảnh cũ
    if (image1Url) {
      update.Image = image1Url;
    } else if (req.body.existingImage) {
      update.Image = req.body.existingImage;
    }

    if (image2Url) {
      update.bgImg = image2Url;
    } else if (req.body.existingBgImage) {
      update.bgImg = req.body.existingBgImage;
    }

    const options = {
      upsert: true, // Creates a new document if no documents match the filter
      new: true, // Returns the modified document if found or the upserted document if created
    };

    const savedBusinessCard = await BusinessCard.findOneAndUpdate(filter, update, options);

    // Cập nhật selectedItems trong User model để đồng bộ
    await User.findByIdAndUpdate(userId, {
      $set: { selectedItems: [{ businessCard: savedBusinessCard._id, subscriptionPlan: plan }] }
    });

    // Sau khi lưu xong, thông báo link cho user
    const user = await User.findById(userId);
    const cardUrl = `/card/${user.username}`;
    const fullUrl = `${req.protocol}://${req.get('host')}${cardUrl}`;

    res.send(`
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tạo Card Thành Công - AT Digital Card</title>
    <link rel="shortcut icon" href="/public/assets/icon.ico">
    <link href="https://fonts.googleapis.com/css2?family=Be+Vietnam+Pro:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Be Vietnam Pro', sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: linear-gradient(135deg, #f8faff 0%, #e8f0fe 100%);
            padding: 20px;
        }
        .success-card {
            background: white;
            border-radius: 24px;
            padding: 48px 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0, 75, 141, 0.15);
        }
        .success-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #10b981, #059669);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
            animation: scaleIn 0.5s ease;
        }
        @keyframes scaleIn {
            0% { transform: scale(0); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }
        .success-icon .material-icons { font-size: 40px; color: white; }
        h1 { color: #1a1a2e; font-size: 24px; font-weight: 700; margin-bottom: 12px; }
        .subtitle { color: #6b7280; font-size: 15px; margin-bottom: 32px; }
        .card-link-box {
            background: #f3f4f6;
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 24px;
        }
        .card-link-label { color: #6b7280; font-size: 12px; margin-bottom: 8px; }
        .card-link {
            color: #004b8d;
            font-size: 14px;
            font-weight: 600;
            word-break: break-all;
            text-decoration: none;
        }
        .card-link:hover { text-decoration: underline; }
        .btn-group { display: flex; gap: 12px; flex-wrap: wrap; }
        .btn {
            flex: 1;
            min-width: 140px;
            padding: 14px 20px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s;
        }
        .btn-primary {
            background: #004b8d;
            color: white;
        }
        .btn-primary:hover { background: #003d73; transform: translateY(-2px); }
        .btn-secondary {
            background: #f3f4f6;
            color: #1a1a2e;
        }
        .btn-secondary:hover { background: #e5e7eb; }
        .copy-btn {
            background: none;
            border: none;
            color: #004b8d;
            cursor: pointer;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 4px;
            margin: 12px auto 0;
        }
        .copy-btn:hover { text-decoration: underline; }
        .footer-text { color: #9ca3af; font-size: 12px; margin-top: 24px; }
    </style>
</head>
<body>
    <div class="success-card">
        <div class="success-icon">
            <span class="material-icons">check</span>
        </div>
        <h1>Tạo Card Thành Công! 🎉</h1>
        <p class="subtitle">Danh thiếp số của bạn đã sẵn sàng để chia sẻ</p>
        
        <div class="card-link-box">
            <div class="card-link-label">Link danh thiếp của bạn</div>
            <a href="${cardUrl}" class="card-link" id="cardLink">${fullUrl}</a>
            <button class="copy-btn" onclick="copyLink()">
                <span class="material-icons" style="font-size:16px">content_copy</span>
                Sao chép link
            </button>
        </div>
        
        <div class="btn-group">
            <a href="${cardUrl}" class="btn btn-primary">
                <span class="material-icons" style="font-size:18px">visibility</span>
                Xem Card
            </a>
            <a href="/my-card" class="btn btn-secondary">
                <span class="material-icons" style="font-size:18px">edit</span>
                Chỉnh sửa
            </a>
        </div>
        
        <p class="footer-text">© 2025 AT Energy JSC. All rights reserved.</p>
    </div>
    
    <script>
        function copyLink() {
            navigator.clipboard.writeText('${fullUrl}');
            const btn = document.querySelector('.copy-btn');
            btn.innerHTML = '<span class="material-icons" style="font-size:16px">check</span> Đã sao chép!';
            setTimeout(() => {
                btn.innerHTML = '<span class="material-icons" style="font-size:16px">content_copy</span> Sao chép link';
            }, 2000);
        }
    </script>
</body>
</html>
    `);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.post('/delete-user/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    // Find the user by ID and remove them
    const deletedUser = await User.findOneAndDelete({ _id: userId });;

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    const users1 = await fetchUserData();
    res.render('admin/user', { users1 });

  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});




function mapFields(formData, section) {
  const fieldNames = formData[`${section}Names`] || [];
  const fieldValues = formData[`${section}Values`] || [];
  const textColors = formData[`${section}TextColors`] || [];
  const textStyles = formData[`${section}TextStyles`] || [];
  const textSizes = formData[`${section}TextSizes`] || [];

  return fieldNames.map((name, idx) => {
    const fieldObj = {
      fieldName: name,
      value: fieldValues[idx] || '',
      textColor: textColors[idx] || '',
      textStyle: textStyles[idx] || '',
      textSize: textSizes[idx] || '',
    };

    // Additional fields based on section
    if (section === 'contactField') {
      fieldObj.icon = formData[`${section}Icons`] ? formData[`${section}Icons`][idx] : '';
    }

    return fieldObj;
  });
}

const normalizeArrayInput = (value) => {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
};

const buildSocialLinks = (platformInputs, urlInputs) => {
  const platforms = normalizeArrayInput(platformInputs);
  const urls = normalizeArrayInput(urlInputs);
  const socialLinks = [];

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i] ? urls[i].trim() : '';
    if (!url) continue;
    const platform = platforms[i] ? platforms[i] : '';
    socialLinks.push({ platform, url });
  }

  return socialLinks;
};

const ensureUniqueUsername = async (base, excludeUserId = null) => {
  const baseValue = base || 'employee';
  let candidate = baseValue;
  let suffix = 1;
  while (true) {
    const existing = await User.findOne({ username: candidate });
    if (!existing || (excludeUserId && existing._id.equals(excludeUserId))) {
      return candidate;
    }
    candidate = `${baseValue}${suffix}`;
    suffix++;
  }
};

const generateEmployeeUsername = async (name, fallback, excludeUserId = null) => {
  let base = slugify(name || '');
  if (!base && fallback) {
    const emailPrefix = fallback.split('@')[0];
    base = slugify(emailPrefix);
  }
  if (!base) {
    base = 'employee';
  }
  return ensureUniqueUsername(base, excludeUserId);
};

const findEmployeeBySlug = async (slug) => {
  if (!slug) return null;
  let employeeRecord = await emp.findOne({ slug });
  if (employeeRecord) return employeeRecord;
  const allEmployees = await emp.find();
  return allEmployees.find(e => slugify(e.name) === slug);
};



app.post('/custompage/:id', upload.fields([{ name: 'image', maxCount: 1 }]), async (req, res) => {
  try {
    const formData = req.body;
    const imageFile = req.files['image'][0];
    const basicInformationFields = mapFields(formData, 'field');
    const contactInfoFields = mapFields(formData, 'contactField');
    const socialMediaFields = mapFields(formData, 'socialField');
    const buttons = [];


    // Iterate over the button fields in the form data
    for (let i = 0; i < formData.buttonFieldNames.length; i++) {
      const button = {
        fieldName: formData.buttonFieldNames[i],
        value: formData.buttonValues[i],
        textStyle: formData.buttonTextStyles[i],
        buttonColor: formData.buttonColors[i],
        buttonSize: formData.buttonSizes[i],
      };
      buttons.push(button);
    }
    const uniqueid = new ObjectId();
    const key = `${uniqueid}_${req.params.id}`;

    const params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: `custompages_img/${key}`,
      Body: file.buffer,
      ContentType: file.mimetype
    };

    const s3UploadResponse = await s3.upload(params).promise();

    const logoUrl = s3UploadResponse.Location;


    // Save the image to MongoDB
    const customizablePage = new cpages({
      _id: uniqueid,
      user: req.params.id,
      image: logoUrl,
      imageSize: formData.imageSize,
      basicInformationFields: basicInformationFields,
      contactInfoFields: contactInfoFields,
      additionalButtons: buttons,
      socialMediaFields: socialMediaFields,
    });

    // Save the data to MongoDB
    await customizablePage.save();
    console.log(customizablePage);
    res.status(201).send('Form submitted successfully!');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }

});


app.get('/add-company', isAdmin, async (req, res) => {
  res.render('admin/add-company');
});


app.get('/company-details', (req, res) => res.redirect('/add-company'));

app.post('/company-details', isAdmin, upload.single('logo'), async (req, res) => {
  try {
    const { name, fullName, cname, cnum, cmail } = req.body;
    const file = req.file;

    const logoUrl = await smartUpload(file, 'company_logo', 'logo') || '/public/assets/admin/img/logo3.png';

    const newCompany = new mcompany({
      _id: new ObjectId(),
      logo: logoUrl,
      name,
      fullName: fullName || name, // Use fullName if provided, otherwise use name
      ceo: { name: cname, contact: cnum, email: cmail },
      status: 1, // Set active by default
    });

    await newCompany.save();

    // Create a CEO User for this company
    const existingUser = await User.findOne({ email: cmail });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash('12345678', 10); // Default password
      const ceoUser = new User({
        username: cname.replace(/\s+/g, '').toLowerCase(),
        email: cmail,
        password: hashedPassword,
        number: cnum,
        role: 'ceo',
        companyId: newCompany._id
      });
      await ceoUser.save();
    } else {
      // Update existing user to CEO role
      existingUser.role = 'ceo';
      existingUser.companyId = newCompany._id;
      await existingUser.save();
    }

    res.redirect('/companies-list');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});


// GET route for editing company
app.get('/edit-company/:companyId', isAdmin, async (req, res) => {
  try {
    const companyId = req.params.companyId;
    const company = await mcompany.findById(companyId);

    if (!company) {
      return res.status(404).send('Company not found');
    }

    res.render('admin/edit-company', { company });
  } catch (error) {
    console.error('Error fetching company for editing:', error);
    res.status(500).send('Internal Server Error');
  }
});

// POST route for updating company
app.post('/edit-company/:companyId', isAdmin, upload.single('logo'), async (req, res) => {
  try {
    const companyId = req.params.companyId;
    const { name, fullName, cname, cnum, cmail } = req.body;
    const file = req.file;

    const company = await mcompany.findById(companyId);
    if (!company) {
      return res.status(404).send('Company not found');
    }

    // Update company information
    company.name = name;
    company.fullName = fullName || name; // Use fullName if provided, otherwise use name
    company.ceo.name = cname;
    company.ceo.contact = cnum;
    company.ceo.email = cmail;

    // Update logo if a new one is provided
    if (file) {
      const logoUrl = await smartUpload(file, 'company_logo', 'logo');
      if (logoUrl) {
        company.logo = logoUrl;
      }
    }

    await company.save();

    // Update CEO user information if exists (using findOneAndUpdate to avoid validation issues)
    await User.findOneAndUpdate(
      { companyId: companyId, role: 'ceo' },
      {
        $set: {
          username: cname.replace(/\s+/g, '').toLowerCase(),
          number: cnum
        }
      },
      { runValidators: false } // Skip validation for fields we're not updating
    );

    res.redirect('/companies-list');
  } catch (error) {
    console.error('Error updating company:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/add-employee', isAdmin, async (req, res) => {
  let company;
  if (res.locals.loggedInUser.role === 'ceo') {
    // CEOs can only add employees to their own company
    company = await mcompany.find({ _id: res.locals.loggedInUser.companyId });
  } else {
    // Super-admins see all companies
    company = await mcompany.find();
  }
  res.render('admin/add-employee', { company });
});

app.post('/add-employee', isAdmin, upload.single('photo'), async (req, res) => {
  try {
    const {
      name, company, contact, phone2, email, website,
      address, videoUrl, imageFit, imagePos,
      rank, designation, empid, bid, area,
      teamSize, experience, achievements
    } = req.body;
    const socialLinks = buildSocialLinks(req.body.socialPlatforms, req.body.socialUrls);
    const file = req.file;

    const photoUrl = await smartUpload(file, 'employee_img', 'photo') || '/public/assets/admin/img/profiles/avatar-01.jpg';

    const employeeSlug = slugify(name) || slugify(email && email.split('@')[0]) || `employee${Date.now()}`;
    const newEmployee = new emp({
      _id: new ObjectId(),
      photo: photoUrl,
      name,
      contact,
      phone2,
      email,
      website,
      address,
      videoUrl,
      imageFit: imageFit || 'cover',
      imagePos: imagePos || '50',
      rank,
      designation,
      employeeid: empid,
      branchid: bid,
      area,
      teamSize: teamSize || 0,
      experience: experience || 0,
      achievements: achievements || '',
      company: company,
      socialLinks: socialLinks,
      slug: employeeSlug
    });

    await newEmployee.save();

    // Auto-create User account for employee
    const existingUser = await User.findOne({ email: email });
    if (!existingUser) {
      const employeeUsername = await generateEmployeeUsername(name, email);
      const defaultPassword = '12345678';
      const hashedPassword = await bcrypt.hash(defaultPassword, 10);

      const employeeUser = new User({
        username: employeeUsername,
        email: email,
        password: hashedPassword,
        number: contact || 0,
        role: 'employee',
        companyId: company,
        employeeId: newEmployee._id
      });
      await employeeUser.save();

      console.log(`✅ Created employee account - Email: ${email}, Password: ${defaultPassword}`);
    } else {
      console.log(`ℹ️ User with email ${email} already exists, skipping account creation`);
    }

    res.redirect('/employee-list');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

// Helper to provide slugify in views
app.locals.slugify = slugify;

// Greedy public profile route has been moved below specific routes to avoid conflicts

app.get('/global/:name', async function (req, res) {
  try {

    const user = await User.find({ username: req.params.name });
    console.log(user);
    const pageData = await cpages.find({ user: user[0].id });
    console.log(pageData[0]);
    // Render the page with the retrieved data
    res.render('admin/globalpage', { pageData: pageData[0] });
  } catch (error) {
    console.error('Error executing Mongoose query:', error);
    // Handle the error appropriately (send an error response, etc.)
    res.status(500).send('Internal Server Error');
  }
});


app.get('/companies-list', isAdmin, async (req, res) => {
  try {

    const companies = await mcompany.find();

    res.render('admin/companies-list', { companies });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.put('/update-company-status/:companyId', async (req, res) => {
  try {
    const companyId = req.params.companyId;
    const { action } = req.body;

    let status;
    if (action === 'activate') {
      status = 1;
    } else if (action === 'deactivate') {
      status = 0;
    } else {
      return res.status(400).json({ message: 'Invalid action' });
    }

    await mcompany.findByIdAndUpdate(companyId, { status });
    res.json({ message: `Company ${action}d successfully` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/delete-company/:companyId', isAdmin, async (req, res) => {
  try {
    const companyId = req.params.companyId;

    // 1. Delete associated employees
    await emp.deleteMany({ company: companyId });

    // 2. Delete the associated CEO users
    await User.deleteMany({ companyId: companyId, role: 'ceo' });

    // 3. Delete the company itself
    const company = await mcompany.findByIdAndDelete(companyId);

    if (!company) {
      return res.status(404).send('Company not found');
    }

    res.redirect('/companies-list');
  } catch (error) {
    console.error('Error deleting company:', error);
    res.status(500).send('Internal Server Error');
  }
});



app.get('/invitation', async (req, res) => {
  res.render('admin/invitations');
});


app.get('/employee-list', isAdmin, async (req, res) => {
  let employees;
  let companies;

  if (res.locals.loggedInUser.role === 'employee') {
    // Employee only sees their own card
    const employeeId = res.locals.loggedInUser.employeeId;
    employees = await emp.find({ _id: employeeId });
    companies = await mcompany.find({ _id: res.locals.loggedInUser.companyId });
  } else if (res.locals.loggedInUser.role === 'ceo') {
    // Filter by companyId for CEOs
    const companyId = res.locals.loggedInUser.companyId;
    employees = await emp.find({ company: companyId });
    companies = await mcompany.find({ _id: companyId });
  } else {
    // Show all for Super Admin
    employees = await emp.find();
    companies = await mcompany.find();
  }

  res.render('admin/employees-list', { employees, companies });
});

// Post request to update employee details
app.post('/edit-employee/:employeeId', upload.single('photo'), async (req, res) => {
  const employeeId = req.params.employeeId;

  try {
    // Retrieve the employee by ID
    const employee = await emp.findById(employeeId);
    const companies = await mcompany.find();

    if (!employee) {
      return res.status(404).json({ error: 'Employee not found' });
    }

    // Check permissions: employee can only edit their own card
    const user = res.locals.loggedInUser;
    if (user && user.role === 'employee' && user.employeeId.toString() !== employeeId) {
      return res.status(403).send('Bạn không có quyền chỉnh sửa thông tin này');
    }

    // Update employee fields
    employee.name = req.body.name;
    employee.company = req.body.company;
    employee.contact = req.body.contact;
    employee.email = req.body.email;
    employee.address = req.body.address;
    employee.phone2 = req.body.phone2;
    employee.website = req.body.website;
    employee.videoUrl = req.body.videoUrl;
    employee.imageFit = req.body.imageFit || 'cover';
    employee.imagePos = req.body.imagePos || '50';
    employee.rank = req.body.rank;
    employee.designation = req.body.designation;
    employee.employeeid = req.body.empid;
    employee.branchid = req.body.bid;
    employee.area = req.body.area;
    employee.teamSize = req.body.teamSize || 0;
    employee.experience = req.body.experience || 0;
    employee.achievements = req.body.achievements || '';
    employee.socialLinks = buildSocialLinks(req.body.socialPlatforms, req.body.socialUrls);
    employee.slug = slugify(req.body.name) || employee.slug || slugify(employee.email ? employee.email.split('@')[0] : '') || employeeId;

    // Update employee photo if a new one is provided
    if (req.file) {
      const photoUrl = await smartUpload(req.file, 'employee_img', 'photo');
      if (photoUrl) {
        employee.photo = photoUrl;
      }
    }

    // Save the updated employee to the database
    await employee.save();

    const employeeUser = await User.findOne({ employeeId: employee._id });
    if (employeeUser) {
      const newUsername = await generateEmployeeUsername(employee.name, employee.email, employeeUser._id);
      employeeUser.username = newUsername;
      if (employeeUser.email !== employee.email) {
        employeeUser.email = employee.email;
      }
      await employeeUser.save();
    }

    // Redirect to the employee listing page
    res.redirect('/employee-list');
  } catch (error) {
    console.error('Error updating employee:', error);
    res.status(500).send('Internal Server Error');
  }
});


app.get('/edit-employee/:employeeId', async (req, res) => {
  try {
    const employeeId = req.params.employeeId;
    const employee = await emp.findById(employeeId);
    const companies = await mcompany.find();

    if (!employee) {
      return res.status(404).json({ error: 'Employee not found' });
    }

    // Check permissions: employee can only edit their own card
    const user = res.locals.loggedInUser;
    if (user.role === 'employee' && user.employeeId.toString() !== employeeId) {
      return res.status(403).send('Bạn không có quyền chỉnh sửa thông tin này');
    }

    const employeeCompany = companies.find(company => company._id.toString() === (employee.company ? employee.company.toString() : '')) || null;
    res.render('admin/edit-employee', { employee, companies, employeeCompany }); // Include 'companies' here
  } catch (error) {
    console.error('Error fetching employee for editing:', error);
    res.status(500).send('Internal Server Error');
  }
});


const removeEmployeeWithUser = async (employeeId) => {
  const employee = await emp.findById(employeeId);
  if (!employee) return null;

  if (
    process.env.S3_BUCKET_NAME &&
    process.env.AWS_ACCESS_KEY_ID &&
    employee.photo &&
    employee.photo.includes('s3.amazonaws.com')
  ) {
    try {
      const key = `employee_img/${employee.company}_${employee._id}`;
      await s3.deleteObject({
        Bucket: process.env.S3_BUCKET_NAME,
        Key: key,
      }).promise();
    } catch (s3Err) {
      console.warn("S3 Delete Warning:", s3Err.message);
    }
  }

  await emp.deleteOne({ _id: employeeId });
  await User.findOneAndDelete({ employeeId: employee._id });
  return employee;
};

app.delete('/delete-employee/:employeeId', isAdmin, async (req, res) => {
  try {
    const deleted = await removeEmployeeWithUser(req.params.employeeId);
    if (!deleted) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.json({ message: 'Employee deleted' });
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/delete-employee/:employeeId', isAdmin, async (req, res) => {
  try {
    const deleted = await removeEmployeeWithUser(req.params.employeeId);
    if (!deleted) {
      return res.status(404).json({ error: 'Employee not found' });
    }
    res.redirect('/employee-list');
  } catch (error) {
    console.error('Error deleting employee:', error);
    res.status(500).send('Internal Server Error');
  }
});

// Public profile route will be moved to bottom

app.get('/user-manager', async (req, res) => {
  try {
    const users1 = await fetchUserData();
    res.render('admin/user-manager', { users1 });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

app.post('/user-manager/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    // Find and delete the user by ID
    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Redirect back to the current page (admin/user-manager)
    res.redirect('/admin/user-manager');
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});




app.get('/view-user/:userId', async (req, res) => {
  const userId = req.params.userId;

  try {
    const user = await User.findById(userId)
      .populate('selectedItems.cardType')
      .populate('selectedItems.template');

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Render the view with the user data and populated cardType and template
    res.render('admin/view-user', { user });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/invitations', async (req, res) => {
  const employees = await emp.find();
  res.render('admin/invitations', { employees });
});


app.get("/custompages", async (req, res) => {
  const employees = await emp.find();
  res.render('admin/custompages', { employees });
}
);

// Greedy public profile route (RE-MOVED TO BOTTOM to avoid route interception)
app.get('/:companyName/:employeeName', async (req, res) => {
  try {
    const { companyName, employeeName } = req.params;

    // 1. Find the company (regardless of status first to give better error messages)
    const allCompanies = await mcompany.find();
    const company = allCompanies.find(c => slugify(c.name) === companyName);

    if (!company) return res.status(404).json({ message: 'Company not found' });
    if (company.status !== 1) return res.status(403).json({ message: 'Company is deactivated' });

    // 2. Find employee within that company
    const employees = await emp.find({ company: company._id });
    const employee = employees.find(e => slugify(e.name) === employeeName);

    if (!employee) return res.status(404).json({ message: 'Employee not found' });

    // 3. Map employee data to bcard format for public-card.ejs compatibility
    const user = {
      _id: employee._id,
      username: slugify(employee.name),
      email: employee.email,
      number: employee.phone
    };

    const fallbackSocialLinks = [];
    ['facebook', 'linkedin', 'zalo', 'tiktok'].forEach(platform => {
      if (employee[platform]) {
        fallbackSocialLinks.push({ platform, url: employee[platform] });
      }
    });

    const socialLinks = (employee.socialLinks && employee.socialLinks.length) ? employee.socialLinks : fallbackSocialLinks;

    const bcard = {
      _id: employee._id,
      Image: employee.photo,
      templateFields: [
        { fieldName: 'Name', fieldValue: employee.name },
        { fieldName: 'Role', fieldValue: employee.designation },
        { fieldName: 'Company', fieldValue: company.fullName || company.name }, // Use fullName for display
        { fieldName: 'Phone1', fieldValue: employee.phone },
        { fieldName: 'Phone2', fieldValue: employee.hotline || '' },
        { fieldName: 'ContactEmail', fieldValue: employee.email },
        { fieldName: 'Address', fieldValue: employee.address },
        { fieldName: 'URL', fieldValue: employee.website || company.website || 'https://at-energy.vn' },
        { fieldName: 'VideoURL', fieldValue: employee.video || '' },
        { fieldName: 'ImageFit', fieldValue: employee.imageFit || 'cover' },
        { fieldName: 'ImagePos', fieldValue: employee.imagePos || '50' }
      ],
      socialLinks
    };
    const cardSlug = employee.slug || slugify(employee.name);
    res.render('user/public-card', { user, bcard, companyData: company, cardSlug });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});
