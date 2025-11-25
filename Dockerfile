# Stage 1: Build Stage
# Edited: Закріплена версія OpenJDK
FROM openjdk:8u382-jdk-bullseye as build

WORKDIR /app

# Copy the source code into the Docker image
# Edited: Копіювання у контейнер лише необхідні файли для збірки Maven-проєкту.
COPY pom.xml .
COPY src ./src
# Install Maven and JDK, then build the project
# Edited: Встановлення пакетів без рекомендованих залежностей. Встановлення maven з фіксованою версією.
# Edited: очищення кешу APT післявстановлення.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        maven=3.6.3-5 && \
    rm -rf /var/lib/apt/lists/*

# Stage 2: Runtime Stage
FROM tomcat:7.0.82-jre8

#Edited: Створення непривієлованого користувача.
RUN useradd -r -u 1001 myLowPrivilegeUser

# Copy the WAR file built in the previous stage
COPY --from=build /app/target/*.war /usr/local/tomcat/webapps/

# Copy the pre-prepared tomcat-users.xml to set up user roles
COPY default-tomcat.xml /usr/local/tomcat/conf/tomcat-users.xml

#Edited: Надання прав каталогу Tomcat
RUN chown -R myLowPrivilegeUser:myLowPrivilegeUser /usr/local/tomcat

# Edited: Запуск контейнер не від root
USER myLowPrivilegeUser

# CMD to start Tomcat
CMD ["catalina.sh", "run"]
