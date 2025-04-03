# EUCYS-learno
learno.me-eucys 2025

## Environment Setup (.env)

Για να ανοιξετε το learno.me locally, φτιάξτε ενα  `.env` αρχείο στο root directory του project και βαλτε το εξης:

```env
# Server Configuration
PORT=3000
NODE_ENV=development

# MongoDB Connection
MONGODB_URI=your_mongodb_connection_string

# Authentication
SESSION_SECRET=your_session_secret

# OpenAI API
OPENAI_API_KEY=your_openai_api_key

# Stripe Payment
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_PUBLIC_KEY=your_stripe_public_key

# Application URLs
BASE_URL=http://localhost:3000
PRODUCTION_URL=https://learno.me

# Email Configuration
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
EMAIL_FROM=Learno <your-email@gmail.com>

# Token Pricing and Other Configurations
# (Add necessary token pricing and additional configurations)
```

Βεβαιωθείτε οτι εχετε αλλάξει ολα τα placeholders με τα δικά σας.

To site ειναι live στο domain : www.learno.me

ΧΑΡΑΛΑΜΠΟΣ ΝΙΚΟΛΑΟΣ ΣΑΓΙΡΗΣ