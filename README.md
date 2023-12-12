
# Weather Forecasting Application

The Weather Forecasting Application is a web-based solution designed for providing accurate and timely weather forecasts. Developed using the Flask web framework for the backend and MongoDB for efficient data management, the application is Dockerized for seamless deployment. This Weather Forecasting Web Application is built upon a foundation of security best practices, ensuring a resilient and trustworthy platform for users.

**Backend - Flask:**

The backend of the application is powered by Flask, a lightweight and flexible Python web framework. Flask simplifies request handling, URL routing, and response generation. Its support for Jinja2 templates aids in creating dynamic web pages, while Flask extensions extend functionality, enabling features like authentication and database integration.

**Database - MongoDB:**

MongoDB, a NoSQL document-oriented database, is employed for data storage. Its schema-less architecture accommodates diverse data types, offering flexibility and scalability. MongoDB's platform independence ensures compatibility across various platforms.

**Dockerized Deployment:**

The entire application is encapsulated within a Dockerized environment, streamlining deployment and enhancing consistency. Docker containers isolate dependencies, contributing to portability and scalability.

## Implemented Standards and Best Practices

### Coding Standards and Best Practices

#### Code Organization

The project follows a well-organized directory layout, facilitating efficient code, asset, and template management. A structured application root directory ensures clarity and scalability.

- **Project File Structure**: The root directory contains the main program code, configuration files, and container-related files.
- **Organizing Templates**: HTML templates are stored in a separate directory, promoting code logic and presentation separation.
- **Static Assets ('static/')**: Assets like CSS and JavaScript files are organized in the 'static' directory.

#### Coding Conventions

The development adheres to the 'PEP 8' style guide for clean, consistent, and readable Python code.

- **Code Formatting and Structure**: Indentation (4 spaces), import statement grouping, and naming conventions follow 'PEP 8'.
- **Line Length**: Maintains a maximum line length of 79 characters for readability.
- **Docstrings**: Used for functions and modules as recommended by 'PEP 8'.
- **Whitespaces**: Strategically used to enhance code readability.
- **Comments**: Composed as complete sentences, inline comments used judiciously.

#### Other Conventions

- **Extending Base Templates**: Utilizes Flask's "extend" concept to break common elements into separate files, improving code maintainability.
- **Routing and Views**: Implements Flask's routing system for clean separation between different program sections.
- **Utilizing Flask's Template Engine (Jinja2)**: Embeds placeholders for dynamic HTML content using Jinja2.

### Security Practices

#### Specific Format Checks

- **Password Format Checks**: Enforces password complexity rules (uppercase, lowercase, digit, special character) and a minimum length of 8 characters.
- **Email Format Checks**: Ensures valid email formats to enhance client-side security.

#### Injection Attacks

- **Dictionary-Based Queries**: Mitigates injection attacks by constructing queries that treat data as data, preventing execution as commands.

#### Authentication and Session Management

- **Session Management**: Implements a secret key for signing sessions, protecting against CSRF attacks.
- **Password Hashing**: Enhances password security using 'bcrypt' for secure hashing.
- **Sensitive Data Exposure**: Secures default data credentials using hashed passwords and defines MongoDB connection details as environment variables.

#### Access Control Issues

- **Regenerate Session on Login**: Prevents session fixation by clearing existing sessions and creating new ones upon user login.

#### Cross-Site Scripting (XSS)

- **Jinja2 Template Engine**: Uses Flask's Jinja2 template engine to render templates, mitigating XSS risks.
- **Input Sanitization**: Escapes or encodes special characters in user input to prevent XSS attacks.

## Libraries/Framework

| Libraries/Framework    | Usage in System Development                                  |
|-----------------------|----------------------------------------------------------|
| Flask                 | Used for building web applications, creating web routes,   |
|                       | handling HTTP requests, and rendering templates.           |
| pymongo               | Used for interacting with MongoDB databases.              |
| bcrypt                | Used for hashing and salting passwords for secure user    |
|                       | authentication.                                           |
| re                    | Used for regular expressions and pattern matching.        |
| secrets               | Used for generating secure random passwords and tokens.   |
| Jinja2                | Used as a template engine for rendering HTML templates    |
|                       | with dynamic data.                                        |
| os                    | Used for various operating system-related functionalities |
| FileSystemLoader      | Used in conjunction with Jinja2 for loading templates     |
| Environment           | Used for configuring and managing the Jinja2 environment  |
| escape                | Used for HTML input sanitization to prevent XSS attacks.  |

## Screenshots

![App Screenshot](https://drive.google.com/uc?id=1gLZFoRdd7zMNLfWPAZBcnH8naPti71uP)

![App Screenshot](https://drive.google.com/uc?id=1s__NG20vAAgeYAL5Dh4cUE-X2VVUbsRj)

![App Screenshot](https://drive.google.com/uc?id=1UVWUBl22fjSI7oS5CC4NyjqPjR-_F5zk)

![App Screenshot](https://drive.google.com/uc?id=1eeGj6xyK529fvmWtjF4t0VmHyeO7KDg-)

## Run Locally

**Prerequisites:**
- Ensure that Git, Docker, and Docker Compose are installed on your local machine.

**Step 1: Clone the Repository**
```bash
git clone https://github.com/rv0fficial/Weather-App.git
cd Weather-App
```

**Step 2: Set Environment Variables**
- Open the `.env` file and configure the MongoDB connection details:
  ```env
  MONGO_HOST=test_mongodb
  MONGO_PORT=27017
  MONGO_USER=root
  MONGO_PASSWORD=pass
  ```

**Step 3: Build and Start Docker Containers**
```bash
docker-compose up
```

**Step 4: Access the Application**
- Open a web browser and navigate to [http://localhost:5000](http://localhost:5000)

**Step 5: Register a New User**
- Click on the "Register" link and fill in the required information.
- Ensure that you follow the specified password and email format rules.

**Step 6: Login**
- After registration, click on the "Login" link and enter your registered email and password.

**Step 7: Explore the Application**
- Once logged in, you can explore the Weather Forecasting Web Application.

**Step 8: Logout**
- To logout, click on the "Logout" link.

**Step 9: Stop Docker Containers**
- In the terminal where Docker Compose is running, press `Ctrl + C` to stop the containers.

Now you have successfully downloaded, built, and run the Weather Forecasting Web Application locally.