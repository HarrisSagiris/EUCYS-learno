const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { PDFDocument } = require('pdf-lib');
const pdf = require('pdf-parse');
const OpenAI = require('openai');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || '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');

// Initialize Express app
const app = express();
const port = process.env.PORT || 3000;

// Configure OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || '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'
});

// Set up middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'flashcard-platform-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production' ? false : false, // Changed to false for production
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax',
    domain: process.env.NODE_ENV === 'production' ? 'learno.me' : undefined // Removed the dot prefix
  },
  name: 'learno.me.sid'
}));
// Set up view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir);
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const filetypes = /pdf|doc|docx|txt|jpeg|jpg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb('Error: Only PDF, DOC, DOCX, TXT, JPG, JPEG, and PNG files are allowed!');
    }
  }
});

// Also support memory storage for image processing
const memoryStorage = multer.memoryStorage();
const uploadMemory = multer({
  storage: memoryStorage,
  fileFilter: (req, file, cb) => {
    const filetypes = /pdf|doc|docx|txt|jpeg|jpg|png/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb('Error: Only PDF, DOC, DOCX, TXT, JPG, JPEG, and PNG files are allowed!');
    }
  }
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://appleidmusic960:Dataking8@tapsidecluster.oeofi.mongodb.net/learno', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Define schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  tokens: { type: Number, default: 0 },
  tokenTransactions: [{
    amount: Number,
    operation: String,
    timestamp: { type: Date, default: Date.now },
    description: String
  }],
  stripeCustomerId: { type: String }
});

const deckSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  isPublic: { type: Boolean, default: false },
  shareId: { type: String, unique: true, sparse: true },
  viewCount: { type: Number, default: 0 },
  type: { type: String, enum: ['flashcard', 'multiple_choice'], default: 'flashcard' },
  language: { type: String, default: 'en' }, // Added language field
  cards: [{
    front: String,
    back: String,
    tags: [String],
    difficulty: { type: Number, default: 0 },
    imageUrl: String,
    options: [String], // For multiple choice questions
    correctOption: Number // Index of the correct option
  }],
  tokensUsed: { type: Number, default: 0 }
});

// Token pricing constants
const TOKEN_PRICES = {
  UPLOAD_BASE: 10,
  CARD_GENERATION: 2,
  IMAGE_GENERATION: 15,
  IMPROVE_CARD: 5
};

// Euro to token conversion rates
const EURO_TO_TOKENS = {
  5: 100,   // 5 euros = 100 tokens
  10: 220,  // 10 euros = 220 tokens (10% bonus)
  20: 500   // 20 euros = 500 tokens (25% bonus)
};

// Create models
const User = mongoose.model('User', userSchema);
const Deck = mongoose.model('Deck', deckSchema);

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }
  res.redirect('/login');
};

// Token check middleware
const hasEnoughTokens = async (req, res, next, requiredTokens) => {
  try {
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    if (user.tokens < requiredTokens) {
      return res.render('insufficient-tokens', { 
        requiredTokens,
        currentTokens: user.tokens,
        user
      });
    }
    
    // Store the user in the request for later use
    req.user = user;
    next();
  } catch (error) {
    console.error('Token check error:', error);
    res.status(500).send('Server error');
  }
};

// Routes
app.get('/', (req, res) => {
  res.render('index', { user: req.session.userId ? true : false });
});

app.get('/register', (req, res) => {
  res.render('register', { tokenPackages: Object.keys(EURO_TO_TOKENS) });
});
// Payment route
app.get('/payment', isAuthenticated, async (req, res) => {
  try {
    const { amount, tokens } = req.query;
    
    if (!amount || !tokens || !EURO_TO_TOKENS[amount]) {
      return res.redirect('/dashboard');
    }
    
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.redirect('/login');
    }
    
    res.render('payment', {
      amount,
      tokens,
      user
    });
  } catch (error) {
    console.error('Payment page error:', error);
    res.status(500).send('Server error');
  }
});

// Process Stripe payment
app.post('/process-payment', isAuthenticated, async (req, res) => {
  try {
    const { amount, tokens, stripeToken } = req.body;
    
    if (!amount || !tokens || !EURO_TO_TOKENS[amount]) {
      return res.status(400).send('Invalid payment information');
    }
    
    // Create a charge using Stripe
    const charge = await stripe.charges.create({
      amount: parseFloat(amount) * 100, // Convert to cents
      currency: 'eur',
      description: `${tokens} tokens purchase`,
      source: stripeToken,
      metadata: {
        user_id: req.session.userId.toString(),
        tokens: tokens
      }
    });
    
    // Update user's token balance
    const user = await User.findById(req.session.userId);
    user.tokens += parseInt(tokens);
    await user.save();
    
    // Redirect to success page or dashboard
    res.redirect('/payment-success?tokens=' + tokens);
  } catch (error) {
    console.error('Payment processing error:', error);
    res.render('payment', {
      amount: req.body.amount,
      tokens: req.body.tokens,
      error: 'Payment failed. Please try again.',
      user: await User.findById(req.session.userId)
    });
  }
});

// Payment success page
app.get('/payment-success', isAuthenticated, async (req, res) => {
  try {
    const { tokens } = req.query;
    const user = await User.findById(req.session.userId);
    
    res.render('payment-success', {
      tokens,
      user
    });
  } catch (error) {
    console.error('Payment success page error:', error);
    res.redirect('/dashboard');
  }
});
// Token purchase page
app.get('/tokenbuy', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    const error = req.query.error;
    
    res.render('buytokens', {
      user,
      tokenPackages: Object.keys(EURO_TO_TOKENS),
      euroToTokens: EURO_TO_TOKENS,
      stripePublicKey: process.env.STRIPE_PUBLIC_KEY || 'pk_test_your_stripe_key',
      error: error
    });
  } catch (error) {
    console.error('Token purchase page error:', error);
    res.redirect('/dashboard');
  }
});

// Process token purchase
app.post('/tokenbuy', isAuthenticated, async (req, res) => {
  try {
    const { amount, isSubscription } = req.body;
    
    if (!amount || !EURO_TO_TOKENS[amount]) {
      return res.status(400).send('Invalid token package selected');
    }
    
    const tokens = EURO_TO_TOKENS[amount];
    const isSubscriptionMode = isSubscription === 'true';
    
    // Create a Stripe checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: {
            name: `${tokens} Tokens Package`,
            description: isSubscriptionMode ? 
              `Monthly subscription for ${tokens} tokens` : 
              `Purchase of ${tokens} tokens for your account`
          },
          unit_amount: parseFloat(amount) * 100, // Convert to cents
          recurring: isSubscriptionMode ? { interval: 'month' } : undefined
        },
        quantity: 1,
      }],
      metadata: {
        user_id: req.session.userId.toString(),
        tokens: tokens.toString(),
        is_subscription: isSubscriptionMode.toString()
      },
      mode: isSubscriptionMode ? 'subscription' : 'payment',
      success_url: `${req.protocol}://${req.get('host')}/payment-success?tokens=${tokens}&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.protocol}://${req.get('host')}/tokenbuy?error=Payment was cancelled`
    });
    
    // Redirect to Stripe checkout page
    res.redirect(303, session.url);
    
  } catch (error) {
    console.error('Token purchase error:', error);
    const errorMessage = error.message || 'Payment failed. Please try again.';
    res.redirect(`/tokenbuy?error=${encodeURIComponent(errorMessage)}`);
  }
});
app.post('/register', async (req, res) => {
  try {
    const { username, email, password, tokenPackage } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user without tokens first
    const user = new User({
      username,
      email,
      password: hashedPassword,
      tokens: 0
    });
    
    await user.save();
    req.session.userId = user._id;
    
    // If user selected a token package, redirect to payment
    if (tokenPackage && EURO_TO_TOKENS[tokenPackage]) {
      return res.redirect(`/payment?amount=${tokenPackage}&tokens=${EURO_TO_TOKENS[tokenPackage]}`);
    }
    
    res.redirect('/dashboard');
  } catch (error) {
    res.render('register', { 
      error: 'Registration failed. Username or email may already be in use.',
      tokenPackages: Object.keys(EURO_TO_TOKENS)
    });
  }
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Debug log
    console.log(`Login attempt for email: ${email}`);
    
    const user = await User.findOne({ email });
    if (!user) {
      console.log(`User not found for email: ${email}`);
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log(`Password mismatch for email: ${email}`);
      return res.render('login', { error: 'Invalid email or password' });
    }
    
    // Set the session
    req.session.userId = user._id;
    
    // Debug log
    console.log(`Login successful for user: ${user._id}`);
    
    // Save the session before redirecting
    req.session.save(err => {
      if (err) {
        console.error('Session save error:', err);
        return res.render('login', { error: 'Login failed - session error' });
      }
      
      // Redirect after successful session save
      res.redirect('/dashboard');
    });
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { error: 'Login failed - server error' });
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const decks = await Deck.find({ userId: req.session.userId });
    const user = await User.findById(req.session.userId);
    res.render('dashboard', { user, decks });
  } catch (error) {
    res.status(500).send('Server error');
  }
});
app.get('/upload', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    // Make sure TOKEN_PRICES is defined
    const TOKEN_PRICES = {
      UPLOAD_BASE: 10,
      CARD_GENERATION: 1,
      YOUTUBE_PROCESSING: 15
      // Add other token prices as needed
    };
    
    res.render('upload', { 
      user,
      tokenCost: TOKEN_PRICES.UPLOAD_BASE,
      youtubeTokenCost: TOKEN_PRICES.YOUTUBE_PROCESSING,
      hasEnoughTokens: user.tokens >= TOKEN_PRICES.UPLOAD_BASE,
      languages: [
        { code: 'en', name: 'English' },
        { code: 'el', name: 'Greek' },
        { code: 'auto', name: 'Auto-detect' }
      ],
      error: null,
      youtubeUrl: null // Add this to track YouTube URL state
    });
  } catch (error) {
    console.error('Error loading upload page:', error);
    res.status(500).send('Server error');
  }
});

app.post('/upload', isAuthenticated, upload.single('document'), async (req, res, next) => {
  // Get requested card count from form, default to 10 if not specified
  const cardCount = parseInt(req.body?.cardCount) || 10;
  const youtubeUrl = req.body?.youtubeUrl;
  
  // Calculate estimated token cost based on requested card count
  let estimatedTokens = TOKEN_PRICES.UPLOAD_BASE + (cardCount * TOKEN_PRICES.CARD_GENERATION);
  
  // Add YouTube processing cost if URL provided
  if (youtubeUrl) {
    estimatedTokens += TOKEN_PRICES.YOUTUBE_PROCESSING;
  }

  // Check if user has enough tokens
  hasEnoughTokens(req, res, () => {
    if (youtubeUrl) {
      // Handle YouTube URL
      processYoutubeUpload(req, res, cardCount);
    } else {
      // Handle file upload
      try {
        if (!req.file && !youtubeUrl) { // Modified check to consider YouTube URL
          return res.render('upload', { 
            error: 'Please upload a file or provide a YouTube URL',
            user: req.user,
            tokenCost: TOKEN_PRICES.UPLOAD_BASE,
            youtubeTokenCost: TOKEN_PRICES.YOUTUBE_PROCESSING,
            hasEnoughTokens: req.user.tokens >= TOKEN_PRICES.UPLOAD_BASE,
            languages: [
              { code: 'en', name: 'English' },
              { code: 'el', name: 'Greek' },
              { code: 'auto', name: 'Auto-detect' }
            ],
            youtubeUrl: youtubeUrl // Pass back the YouTube URL
          });
        }

        const filePath = req.file.path;
        let textContent = '';
        const deckType = req.body?.deckType || 'flashcard'; // Get the deck type from form
        const language = req.body?.language || 'auto'; // Get the language from form

        // Extract text based on file type with proper UTF-8 handling
        const fileExtension = path.extname(req.file.originalname).toLowerCase();
        
        if (fileExtension === '.pdf') {
          const dataBuffer = fs.readFileSync(filePath);
          
          // Configure pdf-parse with proper encoding options
          const options = {
            pagerender: function(pageData) {
              return pageData.getTextContent({ normalizeWhitespace: true })
                .then(function(textContent) {
                  let text = '';
                  for (let item of textContent.items) {
                    text += item.str + ' ';
                  }
                  return text;
                });
            }
          };
          
          const data = await pdf(dataBuffer, options);
          textContent = data.text;
        } else if (fileExtension === '.txt') {
          // Read text file with UTF-8 encoding explicitly
          textContent = fs.readFileSync(filePath, 'utf8');
        } else if (fileExtension === '.docx') {
          // Use mammoth for DOCX extraction with proper character encoding
          const mammoth = require('mammoth');
          
          const result = await mammoth.extractRawText({
            path: filePath,
            convertImage: mammoth.images.imgElement(function(image) {
              return {
                src: image.src
              };
            })
          });
          
          // Ensure proper UTF-8 encoding for international characters
          textContent = result.value;
          
          // Log any warnings for debugging
          if (result.messages.length > 0) {
            console.log("Mammoth warnings:", result.messages);
          }
        } else if (fileExtension === '.jpg' || fileExtension === '.jpeg') {
          // Use Tesseract.js or another OCR library to extract text from images
          const { createWorker } = require('tesseract.js');
          
          const worker = await createWorker();
          
          // Set language based on user selection
          let ocrLanguage = 'eng';
          if (language === 'el') {
            ocrLanguage = 'ell+grc'; // Use both modern Greek (ell) and ancient Greek (grc)
          } else if (language === 'auto') {
            // For auto, we'll use English + Greek as default to improve detection capabilities
            ocrLanguage = 'eng+ell+grc';
          }
          
          // Initialize Tesseract.js worker with the correct language
          await worker.load();
          await worker.loadLanguage(ocrLanguage);
          await worker.setParameters({
            tessedit_ocr_engine_mode: 3, // Legacy engine only mode
          });
          
          // Use worker.recognize directly after loading the language
          // The initialize method is deprecated in newer versions of Tesseract.js
          const { data } = await worker.recognize(filePath);
          textContent = data.text;
          console.log(`Extracted text from image using OCR (${ocrLanguage})`);
          
          await worker.terminate();
        } else {
          // For other file types, you might need additional libraries
          textContent = 'File content extraction not supported for this file type yet.';
        }

        let promptContent = '';
        let flashcards = [];
        let languagePrompt = '';
        
        // Set language-specific instructions
        if (language === 'el') {
          languagePrompt = "Create content in Greek language. Ensure proper handling of Greek characters and grammar.";
        } else if (language === 'auto') {
          languagePrompt = "Detect the language of the content and create flashcards in the same language. If the content contains Greek text, ensure proper handling of Greek characters and grammar.";
        } else {
          languagePrompt = "Create content in English language.";
        }

        if (deckType === 'multiple_choice') {
          // Generate multiple choice questions using OpenAI with language support
          promptContent = `You are a helpful assistant that creates multiple-choice questions from educational content. ${languagePrompt} Create ${cardCount} multiple-choice questions in JSON format with 'front' (the question), 'options' (array of 4 possible answers), and 'correctOption' (index of the correct answer, 0-3) properties. Your response must be ONLY a valid JSON array that can be parsed directly, with no additional text, explanations, or formatting. Example of expected format: [{\"front\":\"What is the capital of France?\",\"options\":[\"London\",\"Berlin\",\"Paris\",\"Madrid\"],\"correctOption\":2}]`;
        } else {
          // Generate regular flashcards using OpenAI with language support
          promptContent = `You are a helpful assistant that creates flashcards from educational content. ${languagePrompt} Create ${cardCount} flashcards in JSON format with 'front' and 'back' properties. The front should be a question or concept, and the back should be the answer or explanation. Your response must be ONLY a valid JSON array that can be parsed directly, with no additional text, explanations, or formatting. Example of expected format: [{\"front\":\"Question 1\",\"back\":\"Answer 1\"},{\"front\":\"Question 2\",\"back\":\"Answer 2\"}]`;
        }

        // Generate content using OpenAI
        const response = await openai.chat.completions.create({
          model: "gpt-4",
          messages: [
            {
              role: "system",
              content: promptContent
            },
            {
              role: "user",
              content: `Create ${cardCount} ${deckType === 'multiple_choice' ? 'multiple-choice questions' : 'flashcards'} from this content: ${textContent.substring(0, 4000)}`
            }
          ],
          temperature: 0.7,
          max_tokens: 2000
        });

        try {
          const content = response.choices[0].message.content.trim();
          console.log("Raw API response:", content);
          
          // Enhanced JSON parsing with multiple fallback strategies
          let parseSuccess = false;
          
          // First attempt: direct parsing
          try {
            flashcards = JSON.parse(content);
            parseSuccess = true;
            console.log("Direct parsing succeeded");
            
            // Check if we got an empty array
            if (Array.isArray(flashcards) && flashcards.length === 0) {
              console.log("Received empty array, creating default cards");
              parseSuccess = false;
            }
          } catch (e) {
            console.log("Direct parsing failed:", e.message);
          }
          
          // Second attempt: extract JSON array using regex if first attempt failed
          if (!parseSuccess) {
            try {
              const jsonMatch = content.match(/\[\s*\{[\s\S]*\}\s*\]/);
              if (jsonMatch) {
                flashcards = JSON.parse(jsonMatch[0]);
                parseSuccess = true;
                console.log("Regex extraction succeeded");
                
                // Check if we got an empty array
                if (Array.isArray(flashcards) && flashcards.length === 0) {
                  console.log("Received empty array from regex, creating default cards");
                  parseSuccess = false;
                }
              }
            } catch (e) {
              console.log("Regex extraction failed:", e.message);
            }
          }
            
            // Third attempt: try to clean the content and parse again
            if (!parseSuccess) {
              try {
                // Remove markdown code blocks
                let cleanedContent = content
                  .replace(/^```json\s*/i, '')
                  .replace(/^```\s*/i, '')
                  .replace(/\s*```$/i, '')
                  .trim();
                  
                // Fix common JSON formatting issues
                cleanedContent = cleanedContent
                  .replace(/(['"])?([a-zA-Z0-9_]+)(['"])?:/g, '"$2":') // Ensure property names are quoted
                  .replace(/'/g, '"'); // Replace single quotes with double quotes
                  
                flashcards = JSON.parse(cleanedContent);
                parseSuccess = true;
                console.log("Cleaned content parsing succeeded");
                
                // Check if we got an empty array
                if (Array.isArray(flashcards) && flashcards.length === 0) {
                  console.log("Received empty array from cleaned content, creating default cards");
                  parseSuccess = false;
                }
              } catch (e) {
                console.log("Cleaned content parsing failed:", e.message);
              }
            }
            
            // Fourth attempt: try to extract individual objects and build array manually
            if (!parseSuccess) {
              try {
                const objectRegex = /\{\s*"front"\s*:\s*"[^"]*"\s*,\s*"back"\s*:\s*"[^"]*"\s*\}/g;
                const mcObjectRegex = /\{\s*"front"\s*:\s*"[^"]*"\s*,\s*"options"\s*:\s*\[[^\]]*\]\s*,\s*"correctOption"\s*:\s*\d+\s*\}/g;
                
                const matches = deckType === 'multiple_choice' 
                  ? content.match(mcObjectRegex) 
                  : content.match(objectRegex);
                  
                if (matches && matches.length > 0) {
                  flashcards = matches.map(match => {
                    try {
                      return JSON.parse(match);
                    } catch (e) {
                      console.log("Failed to parse individual object:", match);
                      return null;
                    }
                  }).filter(card => card !== null);
                  
                  if (flashcards.length > 0) {
                    parseSuccess = true;
                    console.log("Individual object extraction succeeded");
                  }
                }
              } catch (e) {
                console.log("Individual object extraction failed:", e.message);
              }
            }
            
            // Fifth attempt: handle Greek characters specifically
            if (!parseSuccess && (language === 'el' || language === 'auto')) {
              try {
                // Replace any escaped Unicode sequences
                const unicodeFixed = content.replace(/\\u([0-9a-fA-F]{4})/g, (match, p1) => {
                  return String.fromCharCode(parseInt(p1, 16));
                });
                
                // Try parsing again with fixed Unicode
                flashcards = JSON.parse(unicodeFixed);
                parseSuccess = true;
                console.log("Unicode fixing succeeded");
                
                // Check if we got an empty array
                if (Array.isArray(flashcards) && flashcards.length === 0) {
                  console.log("Received empty array after Unicode fixing, creating default cards");
                  parseSuccess = false;
                }
              } catch (e) {
                console.log("Unicode fixing failed:", e.message);
              }
            }
            
            // Special handling for Greek content - extract content directly from text
            if (!parseSuccess && (language === 'el' || language === 'auto')) {
              try {
                console.log("Attempting Greek-specific content extraction");
                
                // Split content by newlines to find potential question/answer pairs
                const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);
                
                if (lines.length >= 2) {
                  flashcards = [];
                  
                  // Try to extract question-answer pairs
                  for (let i = 0; i < lines.length - 1; i += 2) {
                    const front = lines[i].replace(/^[QΕ][:.]\s*|^[0-9]+[.)\]]\s*|^[-*•]\s*/i, '').trim();
                    const back = lines[i+1].replace(/^[AΑ][:.]\s*/i, '').trim();
                    
                    if (front && back) {
                      flashcards.push({ front, back });
                    }
                  }
                  
                  if (flashcards.length > 0) {
                    parseSuccess = true;
                    console.log("Greek content extraction succeeded with", flashcards.length, "cards");
                  }
                }
              } catch (e) {
                console.log("Greek content extraction failed:", e.message);
              }
            }
            
            // Last resort: create a minimal set of cards from the response
            if (!parseSuccess) {
              console.log("All parsing attempts failed, creating fallback cards");
              
              // Create default cards based on language
              if (language === 'el') {
                flashcards = [
                  {
                    front: "Τι είναι η μάθηση;",
                    back: "Η διαδικασία απόκτησης γνώσεων και δεξιοτήτων μέσω μελέτης ή εμπειρίας."
                  },
                  {
                    front: "Πώς λειτουργούν οι κάρτες μελέτης;",
                    back: "Βοηθούν στην απομνημόνευση πληροφοριών μέσω της επαναλαμβανόμενης εξάσκησης και ανάκλησης."
                  }
                ];
              } else {
                flashcards = [
                  {
                    front: "What is learning?",
                    back: "The process of acquiring knowledge and skills through study or experience."
                  },
                  {
                    front: "How do flashcards work?",
                    back: "They help memorize information through spaced repetition and active recall."
                  }
                ];
              }
              
              // Try to extract some content manually
              const frontMatches = content.match(/"front"\s*:\s*"([^"]*)"/g);
              const backMatches = content.match(/"back"\s*:\s*"([^"]*)"/g);
              
              if (frontMatches && backMatches && frontMatches.length === backMatches.length) {
                flashcards = [];
                for (let i = 0; i < Math.min(frontMatches.length, cardCount); i++) {
                  try {
                    const frontMatch = frontMatches[i].match(/"front"\s*:\s*"([^"]*)"/);
                    const backMatch = backMatches[i].match(/"back"\s*:\s*"([^"]*)"/);
                    
                    if (frontMatch && backMatch) {
                      const front = frontMatch[1];
                      const back = backMatch[1];
                      flashcards.push({ front, back });
                    }
                  } catch (e) {
                    console.log("Error extracting match:", e.message);
                  }
                }
                
                if (flashcards.length > 0) {
                  parseSuccess = true;
                  console.log("Created fallback cards from content matches");
                }
              }
            }
            
            // Validate that we have an array of objects with required properties
            if (!Array.isArray(flashcards) || flashcards.length === 0) {
              throw new Error('Response did not contain a valid array of content');
            }
            
            // Ensure each item has required properties based on deck type
            if (deckType === 'multiple_choice') {
              flashcards = flashcards.filter(card => 
                card.front && 
                Array.isArray(card.options) && 
                card.options.length > 0 && 
                typeof card.correctOption === 'number'
              );
              
              // Add empty back field for consistency
              flashcards = flashcards.map(card => ({
                ...card,
                back: card.options[card.correctOption]
              }));
            } else {
              flashcards = flashcards.filter(card => card.front && card.back);
            }
            
            if (flashcards.length === 0) {
              throw new Error(`No valid ${deckType === 'multiple_choice' ? 'questions' : 'flashcards'} found in response`);
            }
          } catch (error) {
            console.error('Error parsing content:', error);
            try {
              const user = await User.findById(req.session.userId);
              return res.render('upload', { 
                error: `Failed to generate ${deckType === 'multiple_choice' ? 'multiple-choice questions' : 'flashcards'}. Please try again.`,
                languages: [
                  { code: 'en', name: 'English' },
                  { code: 'el', name: 'Greek' },
                  { code: 'auto', name: 'Auto-detect' }
                ],
                tokenCost: TOKEN_PRICES.UPLOAD_BASE,
                user: user,
                hasEnoughTokens: user.tokens >= TOKEN_PRICES.UPLOAD_BASE,
                youtubeUrl: youtubeUrl // Pass back the YouTube URL
              });
            } catch (userError) {
              console.error('Error fetching user data:', userError);
              return res.render('upload', { 
                error: `Failed to generate ${deckType === 'multiple_choice' ? 'multiple-choice questions' : 'flashcards'}. Please try again.`,
                languages: [
                  { code: 'en', name: 'English' },
                  { code: 'el', name: 'Greek' },
                  { code: 'auto', name: 'Auto-detect' }
                ],
                youtubeUrl: youtubeUrl // Pass back the YouTube URL
              });
            }
          }

          // Calculate actual tokens used based on generated card count
          const tokensUsed = TOKEN_PRICES.UPLOAD_BASE + (flashcards.length * TOKEN_PRICES.CARD_GENERATION);
          
          // Deduct tokens from user
          const user = await User.findById(req.session.userId);
          user.tokens -= tokensUsed;
          user.tokenTransactions.push({
            amount: -tokensUsed,
            operation: 'deck_creation',
            description: `Created ${deckType} deck with ${flashcards.length} cards in ${language === 'auto' ? 'auto-detected' : language} language`
          });
          await user.save();

          // Create a new deck
          const deck = new Deck({
            title: req.body.title || path.basename(req.file.originalname, path.extname(req.file.originalname)),
            description: req.body.description || `Generated ${deckType} deck from uploaded document`,
            userId: req.session.userId,
            type: deckType,
            language: language,
            cards: flashcards,
            tokensUsed: tokensUsed
          });

          await deck.save();
          
          // Clean up the uploaded file
          fs.unlinkSync(filePath);
          
          res.redirect(`/deck/${deck._id}`);
        } catch (error) {
          console.error('Upload error:', error);
          res.render('upload', { 
            error: 'An error occurred during processing',
            languages: [
              { code: 'en', name: 'English' },
              { code: 'el', name: 'Greek' },
              { code: 'auto', name: 'Auto-detect' }
            ],
            youtubeUrl: youtubeUrl // Pass back the YouTube URL
          });
        }
      });
    }
  }, estimatedTokens);
});

async function processYoutubeUpload(req, res, cardCount) {
  try {
    const youtubeUrl = req.body.youtubeUrl;
    const deckType = req.body.deckType || 'flashcard';
    const language = req.body.language || 'auto';

    // Extract video ID from YouTube URL
    const videoId = youtubeUrl.match(/(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})/i)?.[1];

    if (!videoId) {
      throw new Error('Invalid YouTube URL');
    }

    // Use youtube-transcript-api or similar to get video transcript
    const transcript = await getYoutubeTranscript(videoId);
    
    // Generate flashcards using the transcript
    const response = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: `Create ${cardCount} flashcards from this YouTube video transcript. Format as JSON array with 'front' and 'back' properties.`
        },
        {
          role: "user",
          content: transcript
        }
      ]
    });

    const flashcards = JSON.parse(response.choices[0].message.content);

    // Calculate tokens used
    const tokensUsed = TOKEN_PRICES.YOUTUBE_PROCESSING + (flashcards.length * TOKEN_PRICES.CARD_GENERATION);

    // Deduct tokens and save transaction
    const user = await User.findById(req.session.userId);
    user.tokens -= tokensUsed;
    user.tokenTransactions.push({
      amount: -tokensUsed,
      operation: 'youtube_deck_creation',
      description: `Created deck from YouTube video with ${flashcards.length} cards`
    });
    await user.save();

    // Create new deck
    const deck = new Deck({
      title: req.body.title || 'YouTube Video Deck',
      description: req.body.description || `Generated from YouTube video: ${youtubeUrl}`,
      userId: req.session.userId,
      type: deckType,
      language: language,
      cards: flashcards,
      tokensUsed: tokensUsed,
      youtubeUrl: youtubeUrl
    });

    await deck.save();
    res.redirect(`/deck/${deck._id}`);

  } catch (error) {
    console.error('YouTube processing error:', error);
    res.render('upload', {
      error: 'Failed to process YouTube video',
      languages: [
        { code: 'en', name: 'English' },
        { code: 'el', name: 'Greek' },
        { code: 'auto', name: 'Auto-detect' }
      ],
      youtubeUrl: req.body.youtubeUrl // Pass back the YouTube URL
    });
  }
}
// Search web resources API endpoint
app.post('/api/search-web-resources', isAuthenticated, async (req, res) => {
  try {
    const { deckId, title, description, cards } = req.body;
    
    // Validate input
    if (!deckId || !title || !cards || !Array.isArray(cards)) {
      return res.status(400).json({ success: false, error: 'Invalid request data' });
    }
    
    // Find the deck and verify ownership
    const deck = await Deck.findOne({ _id: deckId, userId: req.session.userId });
    if (!deck) {
      return res.status(404).json({ success: false, error: 'Deck not found or access denied' });
    }
    
    // Find user and check token balance
    const user = await User.findById(req.session.userId);
    // Fix: Use correct token price reference
    const tokenCost = TOKEN_PRICES.WEB_SEARCH;
    
    if (isNaN(tokenCost)) {
      return res.status(500).json({ success: false, error: 'Invalid token price configuration' });
    }
    
    if (user.tokens < tokenCost) {
      return res.status(403).json({ success: false, error: 'Not enough tokens for this operation' });
    }
    
    // Prepare content for search query
    const searchContent = `${title}. ${description}. ${cards.map(card => 
      `Question: ${card.front} Answer: ${card.back}`).join(' ')}`;
    
    // Call OpenAI to search for web resources
    const response = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        { role: "system", content: "You are a helpful assistant that finds relevant web resources for learning materials." },
        { role: "user", content: `Find 5 high-quality web resources (articles, videos, courses) related to this topic: ${searchContent}. For each resource, provide a title, URL, and brief description. Format your response as a JSON string with a 'resources' array containing objects with 'title', 'url', and 'description' fields.` }
      ]
    });
    
    // Parse the response
    let resources = [];
    try {
      const jsonResponse = JSON.parse(response.choices[0].message.content);
      resources = jsonResponse.resources || [];
    } catch (parseError) {
      console.error('Error parsing OpenAI response:', parseError);
      // Attempt to extract data with regex if JSON parsing fails
      const content = response.choices[0].message.content;
      const resourceMatches = content.match(/\{\s*"title":\s*"([^"]+)",\s*"url":\s*"([^"]+)",\s*"description":\s*"([^"]+)"\s*\}/g);
      
      if (resourceMatches) {
        resources = resourceMatches.map(match => {
          try {
            return JSON.parse(match);
          } catch (e) {
            return null;
          }
        }).filter(item => item !== null);
      }
    }
    
    // Deduct tokens from user - ensure we're working with numbers
    const currentTokens = parseInt(user.tokens, 10);
    if (isNaN(currentTokens)) {
      return res.status(500).json({ success: false, error: 'Invalid user token balance' });
    }
    
    user.tokens = currentTokens - tokenCost;
    user.tokenTransactions.push({
      amount: -tokenCost,
      operation: 'web_search',
      description: `Web resource search for deck: ${title}`
    });
    await user.save();
    
    res.json({ success: true, resources });
  } catch (error) {
    console.error('Web search error:', error);
    res.status(500).json({ success: false, error: 'An error occurred during web search' });
  }
});

// Calendar and study schedule route
app.get('/calendar', isAuthenticated, async (req, res) => {
  try {
    // Fetch all decks for the authenticated user
    const decks = await Deck.find({ userId: req.session.userId });
    const user = await User.findById(req.session.userId);
    
    // Check if user has enough tokens for schedule generation
    const hasEnoughTokens = user.tokens >= TOKEN_PRICES.SCHEDULE_GENERATION;
    
    res.render('schedule', { 
      decks, 
      user,
      hasEnoughTokens,
      tokenPrices: TOKEN_PRICES
    });
  } catch (error) {
    console.error('Calendar error:', error);
    res.status(500).send('Server error');
  }
});
// Generate study schedule API endpoint
app.post('/generate-schedule', isAuthenticated, async (req, res) => {
  try {
    const { deckIds, studyPreference, availableHours } = req.body;
    
    // Validate input
    if (!deckIds || !Array.isArray(deckIds) || deckIds.length === 0) {
      return res.status(400).json({ error: 'Please select at least one deck' });
    }
    
    // Find user and check token balance
    const user = await User.findById(req.session.userId);
    if (user.tokens < TOKEN_PRICES.SCHEDULE_GENERATION) {
      return res.status(403).json({ error: 'Not enough tokens for this operation' });
    }
    
    // Fetch selected decks
    const decks = await Deck.find({ 
      _id: { $in: deckIds }, 
      userId: req.session.userId 
    });
    
    if (decks.length === 0) {
      return res.status(404).json({ error: 'No valid decks found' });
    }
    
    // Prepare deck information for the AI
    const deckInfo = decks.map(deck => ({
      id: deck._id.toString(),
      title: deck.title,
      cardCount: deck.cards.length,
      type: deck.type,
      language: deck.language
    }));
    
    // Generate schedule using OpenAI
    try {
      const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          {
            role: "system",
            content: "You are an educational AI assistant that creates optimal study schedules."
          },
          {
            role: "user",
            content: `Create a weekly study schedule for the following flashcard decks: 
            ${JSON.stringify(deckInfo)}. 
            Study preference: ${studyPreference || 'balanced'}. 
            Available hours: ${availableHours || 'flexible'}.
            Format the response as a JSON object with days of the week as keys, and arrays of study sessions as values.
            Each study session should include: deckId, title, startTime, endTime, and focus area.`
          }
        ],
        response_format: { type: "json_object" }
      });
      
      // Ensure we have a valid response
      if (!completion.choices || !completion.choices[0] || !completion.choices[0].message) {
        throw new Error('Invalid response from OpenAI API');
      }
      
      // Parse the JSON response safely
      let schedule;
      try {
        const content = completion.choices[0].message.content.trim();
        schedule = JSON.parse(content);
      } catch (parseError) {
        console.error('JSON parse error:', parseError);
        console.error('Raw content:', completion.choices[0].message.content);
        
        // Attempt to sanitize the response if it's not valid JSON
        const sanitizedContent = completion.choices[0].message.content
          .replace(/^```json/i, '')
          .replace(/```$/i, '')
          .trim();
          
        try {
          schedule = JSON.parse(sanitizedContent);
        } catch (secondParseError) {
          console.error('Second parse attempt failed:', secondParseError);
          throw new Error('Failed to parse schedule data');
        }
      }
      
      // Validate the schedule structure
      if (!schedule || typeof schedule !== 'object') {
        throw new Error('Invalid schedule format');
      }
      
      // Deduct tokens from user
      user.tokens -= TOKEN_PRICES.SCHEDULE_GENERATION;
      user.tokenTransactions.push({
        amount: -TOKEN_PRICES.SCHEDULE_GENERATION,
        operation: 'schedule_generation',
        description: `Generated study schedule for ${decks.length} decks`
      });
      await user.save();
      
      res.json({ 
        success: true, 
        schedule,
        remainingTokens: user.tokens
      });
    } catch (openaiError) {
      console.error('OpenAI API error:', openaiError);
      return res.status(500).json({ 
        error: 'Failed to generate schedule with AI service', 
        details: openaiError.message 
      });
    }
  } catch (error) {
    console.error('Schedule generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate study schedule', 
      details: error.message 
    });
  }
});

app.get('/deck/:id', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.id);
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).send('Deck not found');
    }
    const user = await User.findById(req.session.userId);
    res.render('deck', { 
      deck, 
      user,
      tokenPrices: TOKEN_PRICES
    });
  } catch (error) {
    res.status(500).send('Server error');
  }
});

app.get('/deck/:id/study', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.id);
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).send('Deck not found');
    }
    const user = await User.findById(req.session.userId);
    res.render('study', { deck, user });
  } catch (error) {
    res.status(500).send('Server error');
  }
});

app.get('/shared-deck/:shareId', async (req, res) => {
  try {
    const deck = await Deck.findOne({ shareId: req.params.shareId, isPublic: true });
    
    if (!deck) {
      return res.status(404).send('Shared deck not found');
    }
    
    // Increment view count
    deck.viewCount = (deck.viewCount || 0) + 1;
    await deck.save();
    
    // Get user if logged in
    const user = req.session.userId ? await User.findById(req.session.userId) : null;
    
    res.render('shared-deck', { deck, user });
  } catch (error) {
    res.status(500).send('Server error');
  }
});
app.get('/library', async (req, res) => {
  try {
    // Find all public decks
    const publicDecks = await Deck.find({ isPublic: true })
      .sort({ viewCount: -1, createdAt: -1 }) // Sort by views (descending) then by creation date
      .lean(); // Use lean for better performance when you don't need Mongoose document methods
    
    // Get user info if logged in
    const user = req.session.userId ? await User.findById(req.session.userId) : null;
    
    // Check if user has enough tokens to study public decks
    const hasTokens = user && user.tokens >= 1;
    
    res.render('library', { 
      publicDecks,
      user,
      isAuthenticated: !!req.session.userId,
      hasTokens: hasTokens,
      tokenCost: 1 // Cost to study a public deck
    });
  } catch (error) {
    console.error('Error fetching public decks:', error);
    res.status(500).send('Server error');
  }
});

// Add a route to handle studying public decks with token payment
app.get('/shared-deck/:shareId/study', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findOne({ shareId: req.params.shareId, isPublic: true });
    
    if (!deck) {
      return res.status(404).send('Shared deck not found');
    }
    
    // Get user
    const user = await User.findById(req.session.userId);
    
    // Check if user has enough tokens
    if (user.tokens < 1) {
      return res.redirect(`/shared-deck/${req.params.shareId}?error=Not enough tokens to study this deck`);
    }
    
    // Deduct token and record transaction
    user.tokens -= 1;
    user.tokenTransactions.push({
      amount: -1,
      description: `Studied public deck: ${deck.title}`,
      timestamp: new Date()
    });
    
    await user.save();
    
    // Render study page
    res.render('study', { deck, user });
  } catch (error) {
    console.error('Error studying shared deck:', error);
    res.status(500).send('Server error');
  }
});

app.get('/settings', isAuthenticated, async (req, res) => {
  try {
    // Fetch the user data
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      return res.status(404).send('User not found');
    }
    
    res.render('settings', { 
      user,
      isAuthenticated: true,
      successMessage: req.session.successMessage || '',
      errorMessage: req.session.errorMessage || '',
      tokenPackages: EURO_TO_TOKENS
    });
    
    // Clear the messages after rendering
    req.session.successMessage = '';
    req.session.errorMessage = '';
  } catch (error) {
    console.error('Error fetching user settings:', error);
    res.status(500).send('Server error');
  }
});

app.post('/settings/profile', isAuthenticated, async (req, res) => {
  try {
    const { username, email } = req.body;
    
    // Validate input
    if (!username || !email) {
      req.session.errorMessage = 'Username and email are required';
      return res.redirect('/settings');
    }
    
    // Update user profile
    await User.findByIdAndUpdate(req.session.userId, {
      username,
      email
    });
    
    req.session.successMessage = 'Profile updated successfully';
    res.redirect('/settings');
  } catch (error) {
    console.error('Error updating profile:', error);
    req.session.errorMessage = 'Failed to update profile';
    res.redirect('/settings');
  }
});

app.post('/settings/password', isAuthenticated, async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    
    // Validate input
    if (!currentPassword || !newPassword || !confirmPassword) {
      req.session.errorMessage = 'All password fields are required';
      return res.redirect('/settings');
    }
    
    if (newPassword !== confirmPassword) {
      req.session.errorMessage = 'New passwords do not match';
      return res.redirect('/settings');
    }
    
    // Get user and verify current password
    const user = await User.findById(req.session.userId);
    const isMatch = await bcrypt.compare(currentPassword, user.password);
    
    if (!isMatch) {
      req.session.errorMessage = 'Current password is incorrect';
      return res.redirect('/settings');
    }
    
    // Hash new password and update
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.session.userId, {
      password: hashedPassword
    });
    
    req.session.successMessage = 'Password updated successfully';
    res.redirect('/settings');
  } catch (error) {
    console.error('Error updating password:', error);
    req.session.errorMessage = 'Failed to update password';
    res.redirect('/settings');
  }
});

app.post('/settings/preferences', isAuthenticated, async (req, res) => {
  try {
    const { theme, emailNotifications } = req.body;
    
    // Update user preferences
    await User.findByIdAndUpdate(req.session.userId, {
      preferences: {
        theme: theme || 'dark',
        emailNotifications: emailNotifications === 'on'
      }
    });
    
    req.session.successMessage = 'Preferences updated successfully';
    res.redirect('/settings');
  } catch (error) {
    console.error('Error updating preferences:', error);
    req.session.errorMessage = 'Failed to update preferences';
    res.redirect('/settings');
  }
});

app.post('/deck/:id/card', isAuthenticated, async (req, res) => {
  try {
    const { front, back, tags, options, correctOption, cardType } = req.body;
    const deck = await Deck.findById(req.params.id);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    const newCard = {
      front,
      back,
      tags: tags ? tags.split(',').map(tag => tag.trim()) : []
    };
    
    // If it's a multiple choice card, add options and correct option
    if (cardType === 'multiple_choice' && options) {
      newCard.options = Array.isArray(options) ? options : options.split(',').map(opt => opt.trim());
      newCard.correctOption = parseInt(correctOption) || 0;
    }
    
    // Charge tokens for manual card creation (less than AI generation)
    const tokensToCharge = 1;
    const user = await User.findById(req.session.userId);
    
    if (user.tokens < tokensToCharge) {
      return res.status(402).json({ error: 'Insufficient tokens' });
    }
    
    user.tokens -= tokensToCharge;
    user.tokenTransactions.push({
      amount: -tokensToCharge,
      operation: 'manual_card_creation',
      description: `Added card to deck: ${deck.title}`
    });
    await user.save();
    
    deck.cards.push(newCard);
    deck.tokensUsed += tokensToCharge;
    
    await deck.save();
    res.redirect(`/deck/${deck._id}`);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/improve-card/:deckId/:cardIndex', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    const cardIndex = parseInt(req.params.cardIndex);
    if (isNaN(cardIndex) || cardIndex < 0 || cardIndex >= deck.cards.length) {
      return res.status(400).json({ error: 'Invalid card index' });
    }
    
    // Check if user has enough tokens
    const user = await User.findById(req.session.userId);
    if (user.tokens < TOKEN_PRICES.IMPROVE_CARD) {
      return res.status(402).json({ 
        error: 'Insufficient tokens',
        requiredTokens: TOKEN_PRICES.IMPROVE_CARD,
        currentTokens: user.tokens
      });
    }
    
    const card = deck.cards[cardIndex];
    
    // Use OpenAI to improve the card
    const response = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: "You are a helpful assistant that improves flashcards. Make the content more clear, concise, and educational."
        },
        {
          role: "user",
          content: `Improve this flashcard:\nFront: ${card.front}\nBack: ${card.back}`
        }
      ],
      temperature: 0.7
    });
    
    const improvedContent = response.choices[0].message.content;
    const frontMatch = improvedContent.match(/Front:(.*?)(?=Back:|$)/s);
    const backMatch = improvedContent.match(/Back:(.*?)(?=$)/s);
    
    if (frontMatch && backMatch) {
      const improvedFront = frontMatch[1].trim();
      const improvedBack = backMatch[1].trim();
      
      deck.cards[cardIndex].front = improvedFront;
      deck.cards[cardIndex].back = improvedBack;
      
      // Deduct tokens
      user.tokens -= TOKEN_PRICES.IMPROVE_CARD;
      user.tokenTransactions.push({
        amount: -TOKEN_PRICES.IMPROVE_CARD,
        operation: 'improve_card',
        description: `Improved card in deck: ${deck.title}`
      });
      await user.save();
      
      // Update deck tokens used
      deck.tokensUsed += TOKEN_PRICES.IMPROVE_CARD;
      await deck.save();
      
      res.json({ 
        success: true, 
        card: deck.cards[cardIndex],
        tokensRemaining: user.tokens
      });
    } else {
      res.status(500).json({ error: 'Failed to parse improved content' });
    }
  } catch (error) {
    console.error('Error improving card:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Chatbot route
app.get('/chatbot', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      return res.redirect('/login');
    }
    
    res.render('chatbot', {
      user: user,
      tokensRemaining: user.tokens
    });
  } catch (error) {
    console.error('Error loading chatbot page:', error);
    res.status(500).send('Server error');
  }
});
// Document upload for chatbot
app.post('/api/upload-document', isAuthenticated, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Check file size (max 10MB)
    if (req.file.size > 10 * 1024 * 1024) {
      return res.status(400).json({ error: 'File size exceeds 10MB limit' });
    }
    
    // Check file type
    const allowedTypes = ['.pdf', '.txt', '.docx'];
    const fileExt = path.extname(req.file.originalname).toLowerCase();
    if (!allowedTypes.includes(fileExt)) {
      return res.status(400).json({ error: 'Unsupported file type. Please upload PDF, TXT, or DOCX files.' });
    }
    
    // Get user to check tokens
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
    
    // Check if user has enough tokens
    const tokensRequired = TOKEN_PRICES.DOCUMENT_ANALYSIS || 10; // Default to 10 if not defined
    if (user.tokens < tokensRequired) {
      return res.status(402).json({ 
        error: 'Insufficient tokens',
        requiredTokens: tokensRequired,
        currentTokens: user.tokens
      });
    }
    
    // Process the file based on its type
    let fileContent = '';
    
    if (fileExt === '.txt') {
      fileContent = fs.readFileSync(req.file.path, 'utf8');
    } else if (fileExt === '.pdf') {
      // For PDF processing, you would need a PDF parsing library
      // This is a placeholder for the actual implementation
      fileContent = `PDF file uploaded: ${req.file.originalname}`;
    } else if (fileExt === '.docx') {
      // For DOCX processing, you would need a DOCX parsing library
      // This is a placeholder for the actual implementation
      fileContent = `DOCX file uploaded: ${req.file.originalname}`;
    }
    
    // Deduct tokens
    user.tokens -= tokensRequired;
    user.tokenTransactions.push({
      amount: -tokensRequired,
      operation: 'document_analysis',
      description: `Analyzed document: ${req.file.originalname}`
    });
    await user.save();
    
    // Return success response
    res.json({
      success: true,
      message: 'Document uploaded and processed successfully.',
      tokensRemaining: user.tokens
    });
    
  } catch (error) {
    console.error('Error processing document:', error);
    res.status(500).json({ error: 'Server error processing document' });
  } finally {
    // Clean up the uploaded file
    if (req.file && req.file.path) {
      fs.unlink(req.file.path, (err) => {
        if (err) console.error('Error deleting temporary file:', err);
      });
    }
  }
});

// Chat API endpoint
app.post('/api/chat', isAuthenticated, async (req, res) => {
  try {
    const { message, conversationId, mode } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    // Get user to check tokens
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
    
    // Determine token cost based on mode
    let tokenCost = TOKEN_PRICES.CHAT_MESSAGE || 1; // Default to 1 if not defined
    let systemPrompt = "You are a helpful AI learning assistant that helps users understand concepts, answer questions, and provide educational support.";
    
    // Adjust token cost and system prompt based on mode
    if (mode === 'code') {
      tokenCost = TOKEN_PRICES.CODE_MODE || 2;
      systemPrompt = "You are a programming expert. Provide clean, efficient, and well-commented code examples. Format your responses as code blocks with appropriate syntax highlighting.";
    } else if (mode === 'web_search') {
      tokenCost = TOKEN_PRICES.WEB_SEARCH || 3;
      systemPrompt = "You are a research assistant with access to web information. Provide comprehensive answers based on current information, citing sources when possible.";
    } else if (mode === 'deep_think') {
      tokenCost = TOKEN_PRICES.DEEP_THINK || 4;
      systemPrompt = "You are a deep analytical thinker. Provide thorough, nuanced analysis of complex topics, considering multiple perspectives and exploring implications in depth.";
    }
    
    // Check if user has enough tokens
    if (user.tokens < tokenCost) {
      return res.status(402).json({ 
        error: 'Insufficient tokens',
        requiredTokens: tokenCost,
        currentTokens: user.tokens
      });
    }
    
    // Call OpenAI API for chat completion
    const completion = await openai.chat.completions.create({
      model: mode === 'deep_think' ? "gpt-4" : "gpt-3.5-turbo",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message }
      ],
      max_tokens: mode === 'deep_think' ? 2000 : 1000
    });
    
    // Get the response text
    const response = completion.choices[0].message.content;
    
    // Ensure token cost is a valid number
    const tokenAmount = Number(tokenCost);
    if (isNaN(tokenAmount)) {
      return res.status(500).json({ error: 'Invalid token cost configuration' });
    }
    
    // Determine operation description based on mode
    let operationDescription = 'AI Assistant chat';
    if (mode === 'code') {
      operationDescription = 'Code assistance';
    } else if (mode === 'web_search') {
      operationDescription = 'Web search assistance';
    } else if (mode === 'deep_think') {
      operationDescription = 'Deep thinking analysis';
    }
    
    // Deduct tokens
    user.tokens = Number(user.tokens) - tokenAmount;
    user.tokenTransactions.push({
      amount: -tokenAmount,
      operation: mode ? `${mode}_mode` : 'chat_message',
      description: operationDescription
    });
    await user.save();
    
    res.json({ 
      response: response,
      tokensRemaining: user.tokens,
      mode: mode || 'standard'
    });
  } catch (error) {
    console.error('Error in AI Assistant API:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/generate-image/:deckId/:cardIndex', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    const cardIndex = parseInt(req.params.cardIndex);
    if (isNaN(cardIndex) || cardIndex < 0 || cardIndex >= deck.cards.length) {
      return res.status(400).json({ error: 'Invalid card index' });
    }
    
    // Check if user has enough tokens
    const user = await User.findById(req.session.userId);
    if (user.tokens < TOKEN_PRICES.IMAGE_GENERATION) {
      return res.status(402).json({ 
        error: 'Insufficient tokens',
        requiredTokens: TOKEN_PRICES.IMAGE_GENERATION,
        currentTokens: user.tokens
      });
    }
    
    const card = deck.cards[cardIndex];
    
    // Generate an image based on the card content
    const response = await openai.images.generate({
      model: "dall-e-3",
      prompt: `Create an educational illustration for a flashcard about: ${card.front}`,
      n: 1,
      size: "1024x1024"
    });
    
    const imageUrl = response.data[0].url;
    
    // Deduct tokens
    user.tokens -= TOKEN_PRICES.IMAGE_GENERATION;
    user.tokenTransactions.push({
      amount: -TOKEN_PRICES.IMAGE_GENERATION,
      operation: 'generate_image',
      description: `Generated image for card in deck: ${deck.title}`
    });
    await user.save();
    
    // Save the image URL to the card
    deck.cards[cardIndex].imageUrl = imageUrl;
    deck.tokensUsed += TOKEN_PRICES.IMAGE_GENERATION;
    await deck.save();
    
    res.json({ 
      success: true, 
      imageUrl,
      tokensRemaining: user.tokens
    });
  } catch (error) {
    console.error('Error generating image:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// API endpoint to convert summary to flashcards
app.post('/api/convert-to-flashcards', isAuthenticated, async (req, res) => {
  try {
    const { content } = req.body;
    
    if (!content) {
      return res.status(400).json({ error: 'No content provided' });
    }
    
    // Check if user has enough tokens
    const user = await User.findById(req.session.userId);
    const tokenCost = TOKEN_PRICES.FLASHCARD_CONVERSION || 5; // Default cost if not defined
    
    if (user.tokens < tokenCost) {
      return res.status(402).json({ 
        error: 'Insufficient tokens',
        requiredTokens: tokenCost,
        currentTokens: user.tokens
      });
    }
    
    // Generate flashcards from the content using OpenAI
    const completion = await openai.chat.completions.create({
      model: "gpt-4",
      messages: [
        {
          role: "system",
          content: "You are an educational assistant that converts text summaries into flashcards. Create flashcards with a clear front (question/term) and back (answer/definition)."
        },
        {
          role: "user",
          content: `Convert the following content into 5-10 flashcards in JSON format with 'front' and 'back' fields:\n\n${content}`
        }
      ],
      response_format: { type: "json_object" }
    });
    
    const flashcardsData = JSON.parse(completion.choices[0].message.content);
    
    // Create a temporary preview in the database
    const previewId = new mongoose.Types.ObjectId();
    const flashcardsPreview = {
      _id: previewId,
      userId: req.session.userId,
      cards: flashcardsData.cards || [],
      originalContent: content,
      createdAt: new Date()
    };
    
    // Store in a temporary collection or in a session
    // For simplicity, we'll use a global variable here, but in production
    // you should use a database collection or Redis
    if (!global.flashcardsPreviewCache) {
      global.flashcardsPreviewCache = {};
    }
    global.flashcardsPreviewCache[previewId] = flashcardsPreview;
    
    // Deduct tokens
    user.tokens -= tokenCost;
    user.tokenTransactions.push({
      amount: -tokenCost,
      operation: 'convert_to_flashcards',
      description: 'Converted summary to flashcards'
    });
    await user.save();
    
    res.json({ 
      success: true, 
      previewId: previewId,
      tokensRemaining: user.tokens
    });
  } catch (error) {
    console.error('Error converting to flashcards:', error);
    res.status(500).json({ error: 'Server error' });
  }
});
// Route to display the summarize page
app.get('/summarise', isAuthenticated, (req, res) => {
  res.render('summarise', { 
    user: req.session.user,
    tokenPrices: TOKEN_PRICES
  });
});

// Route to handle document summarization
app.post('/summarize', isAuthenticated, upload.single('document'), async (req, res) => {
  try {
    const { summaryType, outputFormat } = req.body;
    let tokenCost = TOKEN_PRICES.SUMMARIZE || 5; // Base cost
    
    // Add costs based on options
    if (summaryType === 'detailed') {
      tokenCost += 2;
    } else if (summaryType === 'keypoints') {
      tokenCost += 1;
    }
    
    if (outputFormat === 'flashcards') {
      tokenCost += 3;
    } else if (outputFormat === 'quiz') {
      tokenCost += 4;
    }
    
    // Check if user has enough tokens
    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(401).render('login', { error: 'User not found. Please login again.' });
    }
    
    if (user.tokens < tokenCost) {
      return res.render('summarise', { 
        user: req.session.user,
        tokenPrices: TOKEN_PRICES,
        error: 'Insufficient tokens for this operation'
      });
    }
    
    // Process the uploaded file
    if (!req.file) {
      return res.render('summarise', { 
        user: req.session.user,
        tokenPrices: TOKEN_PRICES,
        error: 'No file uploaded'
      });
    }
    // Check file type
    const fileType = req.file.mimetype;
    if (!fileType.includes('pdf') && !fileType.includes('text/plain') && !fileType.includes('application/vnd.openxmlformats-officedocument.wordprocessingml.document') && !fileType.includes('image/jpeg') && !fileType.includes('image/jpg') && !fileType.includes('image/png')) {
      return res.render('summarise', { 
        user: req.session.user,
        tokenPrices: TOKEN_PRICES,
        error: 'Only PDF, TXT, DOCX, JPG, and PNG files are supported'
      });
    }
    
    let extractedText = '';
    
    // Extract text based on file type
    if (fileType.includes('pdf')) {
      // Extract text from PDF using pdf-parse
      const pdfParse = require('pdf-parse');
      const pdfBuffer = req.file.buffer;
      
      try {
        // Create a Uint8Array from the buffer to fix the invalid parameter error
        const uint8Array = new Uint8Array(pdfBuffer);
        const pdfData = await pdfParse(uint8Array);
        extractedText = pdfData.text;
      } catch (pdfError) {
        console.error('Error parsing PDF:', pdfError);
        return res.render('summarise', { 
          user: req.session.user,
          tokenPrices: TOKEN_PRICES,
          error: 'Error parsing the PDF file. Please ensure it is a valid PDF.'
        });
      }
    } else if (fileType.includes('text/plain')) {
      // For text files, just read the buffer as text
      extractedText = req.file.buffer.toString('utf8');
    } else if (fileType.includes('application/vnd.openxmlformats-officedocument.wordprocessingml.document')) {
      // For DOCX files, use a library like mammoth
      const mammoth = require('mammoth');
      try {
        const result = await mammoth.extractRawText({ buffer: req.file.buffer });
        extractedText = result.value;
      } catch (docxError) {
        console.error('Error parsing DOCX:', docxError);
        return res.render('summarise', { 
          user: req.session.user,
          tokenPrices: TOKEN_PRICES,
          error: 'Error parsing the DOCX file. Please ensure it is a valid document.'
        });
      }
    } else if (fileType.includes('image/jpeg') || fileType.includes('image/jpg') || fileType.includes('image/png')) {
      // For image files, use OCR to extract text
      try {
        const { createWorker } = require('tesseract.js');
        const worker = await createWorker();
        
        // Load both English and Greek languages for OCR
        await worker.loadLanguage('eng+ell+grc');
        await worker.initialize('eng+ell+grc');
        
        const { data } = await worker.recognize(req.file.buffer);
        extractedText = data.text;
        
        await worker.terminate();
      } catch (ocrError) {
        console.error('Error performing OCR on image:', ocrError);
        return res.render('summarise', { 
          user: req.session.user,
          tokenPrices: TOKEN_PRICES,
          error: 'Error extracting text from the image. Please ensure it contains clear text.'
        });
      }
    }
    
    // Check if text was extracted
    if (!extractedText || extractedText.trim().length === 0) {
      return res.render('summarise', { 
        user: req.session.user,
        tokenPrices: TOKEN_PRICES,
        error: 'Could not extract text from the file. The file might be empty or protected.'
      });
    }
    
    // Generate summary using OpenAI
    let prompt = `Summarize the following text in a ${summaryType} format:\n\n${extractedText}`;
    let cards = [];
    
    if (outputFormat === 'flashcards') {
      prompt = `Convert the following text into 5-10 flashcards with key concepts and explanations:\n\n${extractedText}`;
      
      const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          { 
            role: "system", 
            content: "You are an educational assistant that creates flashcards. Each flashcard should have a front (question/term) and back (answer/definition)." 
          },
          { role: "user", content: prompt }
        ],
        response_format: { type: "json_object" }
      });
      
      try {
        const flashcardsData = JSON.parse(completion.choices[0].message.content);
        cards = flashcardsData.cards || [];
      } catch (jsonError) {
        console.error('Error parsing JSON from OpenAI:', jsonError);
        // If JSON parsing fails, create a text summary instead
        const summary = completion.choices[0].message.content;
        return res.render('summarise', {
          user: req.session.user,
          tokenPrices: TOKEN_PRICES,
          summary: summary,
          summaryType: summaryType,
          outputFormat: 'summary',
          error: 'Error creating flashcards, showing text summary instead'
        });
      }
    } else if (outputFormat === 'quiz') {
      prompt = `Create a quiz with 5-10 questions and answers based on the following text:\n\n${extractedText}`;
      
      const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          { 
            role: "system", 
            content: "You are an educational assistant that creates quiz questions. Each quiz item should have a question (front) and answer (back)." 
          },
          { role: "user", content: prompt }
        ],
        response_format: { type: "json_object" }
      });
      
      try {
        const quizData = JSON.parse(completion.choices[0].message.content);
        cards = quizData.questions || [];
      } catch (jsonError) {
        console.error('Error parsing JSON from OpenAI:', jsonError);
        // If JSON parsing fails, create a text summary instead
        const summary = completion.choices[0].message.content;
        return res.render('summarise', {
          user: req.session.user,
          tokenPrices: TOKEN_PRICES,
          summary: summary,
          summaryType: summaryType,
          outputFormat: 'summary',
          error: 'Error creating quiz, showing text summary instead'
        });
      }
    } else {
      // Regular text summary
      const completion = await openai.chat.completions.create({
        model: "gpt-4",
        messages: [
          { role: "system", content: "You are an educational assistant that creates concise and informative summaries." },
          { role: "user", content: prompt }
        ]
      });
      
      const summary = completion.choices[0].message.content;
      
      // Deduct tokens
      user.tokens -= tokenCost;
      user.tokenTransactions.push({
        amount: -tokenCost,
        operation: 'document_summary',
        description: `Generated ${summaryType} summary in ${outputFormat} format`
      });
      await user.save();
      
      return res.render('summarise', {
        user: req.session.user,
        tokenPrices: TOKEN_PRICES,
        summary: summary,
        summaryType: summaryType,
        outputFormat: outputFormat
      });
    }
    
    // Deduct tokens for flashcards or quiz
    user.tokens -= tokenCost;
    user.tokenTransactions.push({
      amount: -tokenCost,
      operation: 'document_summary',
      description: `Generated ${summaryType} summary in ${outputFormat} format`
    });
    await user.save();
    
    res.render('summarise', {
      user: req.session.user,
      tokenPrices: TOKEN_PRICES,
      cards: cards,
      summaryType: summaryType,
      outputFormat: outputFormat
    });
  } catch (error) {
    console.error('Error summarizing document:', error);
    res.render('summarise', { 
      user: req.session.user,
      tokenPrices: TOKEN_PRICES,
      error: 'Error processing your request: ' + (error.message || 'Unknown error')
    });
  }
});

// API endpoint to get user token balance
app.get('/api/user/token-balance', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    
    res.json({ 
      success: true, 
      tokens: user.tokens 
    });
  } catch (error) {
    console.error('Error fetching token balance:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error' 
    });
  }
});

// API endpoint to share a deck
app.post('/api/share-deck/:deckId', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    // Generate a unique share ID if it doesn't exist
    if (!deck.shareId) {
      // Use Node.js built-in crypto module
      const crypto = require('crypto');
      deck.shareId = crypto.randomBytes(8).toString('hex');
      await deck.save();
    }
    
    res.json({ success: true, shareId: deck.shareId });
  } catch (error) {
    console.error('Error sharing deck:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to make a deck public
app.post('/api/make-public/:deckId', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    // Set the deck to public
    deck.isPublic = true;
    await deck.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error making deck public:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to make a deck private
app.post('/api/make-private/:deckId', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).json({ error: 'Deck not found' });
    }
    
    // Set the deck to private
    deck.isPublic = false;
    await deck.save();
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error making deck private:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route to view a shared deck
app.get('/shared-deck/:shareId', async (req, res) => {
  try {
    const deck = await Deck.findOne({ shareId: req.params.shareId });
    
    if (!deck) {
      return res.status(404).send('Shared deck not found');
    }
    
    // Increment view count
    deck.viewCount = (deck.viewCount || 0) + 1;
    await deck.save();
    
    res.render('shared-deck', { deck });
  } catch (error) {
    console.error('Error viewing shared deck:', error);
    res.status(500).send('Server error');
  }
});

app.get('/export/:deckId', isAuthenticated, async (req, res) => {
  try {
    const deck = await Deck.findById(req.params.deckId);
    
    if (!deck || deck.userId.toString() !== req.session.userId.toString()) {
      return res.status(404).send('Deck not found');
    }
    
    // Create a PDF document
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([600, 800]);
    const { width, height } = page.getSize();
    
    page.drawText(`Deck: ${deck.title}`, {
      x: 50,
      y: height - 50,
      size: 20
    });
    
    page.drawText(`Description: ${deck.description}`, {
      x: 50,
      y: height - 80,
      size: 12
    });
    
    let yPosition = height - 120;
    
    deck.cards.forEach((card, index) => {
      if (yPosition < 100) {
        const newPage = pdfDoc.addPage([600, 800]);
        yPosition = height - 50;
      }
      
      page.drawText(`Card ${index + 1}:`, {
        x: 50,
        y: yPosition,
        size: 14
      });
      
      yPosition -= 25;
      
      page.drawText(`Front: ${card.front}`, {
        x: 70,
        y: yPosition,
        size: 12
      });
      
      yPosition -= 20;
      
      if (deck.type === 'multiple_choice' && card.options) {
        page.drawText(`Options:`, {
          x: 70,
          y: yPosition,
          size: 12
        });
        
        yPosition -= 20;
        
        card.options.forEach((option, optIndex) => {
          const prefix = optIndex === card.correctOption ? '✓ ' : '  ';
          page.drawText(`${prefix}${optIndex + 1}. ${option}`, {
            x: 90,
            y: yPosition,
            size: 12
          });
          yPosition -= 15;
        });
      } else {
        page.drawText(`Back: ${card.back}`, {
          x: 70,
          y: yPosition,
          size: 12
        });
        yPosition -= 20;
      }
      
      yPosition -= 20;
    });
    
    const pdfBytes = await pdfDoc.save();
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${deck.title}.pdf"`);
    res.send(Buffer.from(pdfBytes));
  } catch (error) {
    console.error('Export error:', error);
    res.status(500).send('Error exporting deck');
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
