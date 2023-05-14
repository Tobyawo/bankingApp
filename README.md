<h1 align="center">
  <br>
  <a href="https://github.com/zoltanvin/royal-reserve-bank"><img src="https://github.com/zoltanvin/royal-reserve-bank/blob/main/assets/logo.png" alt="Mini Shopify" width="200"></a>
  <br>
  Royal Reserve Bank
  <br>
</h1>

<h3 align="center">Experience the first-class service</a></h3>
<p align="center">
  <a href="#about-">About</a> •
  <a href="#microservices-">Microservices</a> •
  <a href="#solution-architecture-">Architecture</a> •
  <a href="#clone-and-use-">Clone And Use</a> •
  <a href="#technologies-used-">Technologies Used</a>
</p>

# About 🚀

The Royal Reserve Bank is a digital banking platform built using microservices architecture, focused on using the latest Spring Cloud technologies along with Spring Boot to implement various architectural patterns such as service discovery, centralized configuration, distributed tracing, circuit breaker, centralized logging and event-driven architecture.

The platform is built using multiple microservices, including the Account API, Transaction API, Asset Management API and Notification API. These microservices communicate with each other synchronously and asynchronously to perform various banking activities, such as account creation, money transfers, asset management and sending email or SMS notifications. The project also uses message queues like RabbitMQ and Kafka for asynchronous communication.

The solution architecture of the project includes the use of MongoDB and MySQL databases for data storage, API Gateway as a gateway for user requests, and surrounding services that enable the microservice architecture.

Utilized log analysis and monitoring tools such as Elasticsearch, Logstash and Kibana for searching, analyzing, and visualizing logs in the central repository.

# Microservices 📋

1. **Account API** for managing accounts. It acts as an account catalog and communicates with a MongoDB database.
2. **Transaction API** for processing transactions. It communicates with a MySQL database.
3. **Asset Management API** for checking the availability of assets. It also communicates with a MySQL database.
4. **Notification API** sends notifications to customers. It is stateless and does not have a database.
5. **API Gateway** provides a single entry point for customers to communicate with the microservices. It routes customer requests to the appropriate microservice and handles authentication, authorization, and security.

- The Transaction API communicates with the Account API and Asset Management API synchronously to check the availability of funds and assets before processing any transaction. It also communicates with the Notification API asynchronously to send notifications after a successful transaction.
# Solution Architecture 🔍

![image](https://github.com/zoltanvin/royal-reserve-bank/blob/main/assets/high_level_architecture.png)


<details>
  <summary>More detail</summary>

test
</details>

# Clone And Use 🔨

Prerequisites

- Make sure you have Java 17, MongoDB, Docker, MySQL, Maven, Spring Boot, Spring Cloud, Kibana and a compatible IDE (e.g. IntelliJ IDEA, Eclipse) installed and configured.

To run the application using Docker:

- Build the application by running `mvn clean package -DskipTests` and create the docker image locally.
- Start the applications using Docker Compose by running `docker-compose up`.

To run the application without Docker:

- Build the application by running `mvn clean verify -DskipTests` inside each folder.
- Start the applications by running `mvn spring-boot:run` inside each folder.

# Technologies Used 💡

- **Spring Boot:** for simplifying the development and deployment of microservices by using pre-configured templates and tools.
- **Spring Cloud:** for implementing microservices architectural patterns, such as service discovery, configuration management, and circuit breakers.
- **MongoDB:** for storing account data in the Account API allowing flexibility and scalability in handling large amounts of unstructured data.
- **MySQL:** for storing transactions and asset data in the Transaction API and Asset Management API.
- **Kafka:** for implementing asynchronous communication between microservices.
- **API Gateway:** for managing and routing API requests from users to different microservices and providing a unified entry point.
- **JPA:** for implementing the Object Relational Mapping in the microservices, allowing Java applications to interact with databases and perform CRUD.
- **Docker:** for containerization of microservices, making it easy to package and deploy the microservices across different environments.
- **Grafana:** for monitoring and logging the microservices, providing insights into the performance and health of the microservices.

<details>
  <summary>Notes for myself</summary>

cmd docker login registry.hub.docker.com
mvn clean compile jib:build

http://localhost:8761/
http://localhost:4000/actuator/health
http://localhost:9411/
http://localhost:9090/
http://localhost:3000/

</details>

</br>
⭐ Star me on GitHub — it helps!
