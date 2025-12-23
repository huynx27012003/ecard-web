# Use the official Node.js image as the base image
FROM node:16-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json to the working directory
COPY package*.json ./


# Install project dependencies
RUN npm install

# Build static files
RUN npm run build

# Copy the rest of the application code to the working directory
COPY . .

# Expose the port on which the application will run
EXPOSE 3000

# Set environment variables (optional)
ENV NODE_ENV=production

# Command to run the application
CMD ["npm", "start"]
