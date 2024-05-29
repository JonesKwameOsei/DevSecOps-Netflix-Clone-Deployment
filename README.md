# DevSecOps Project: Provisioning a Kubernetes Cluster with Terraform, Jenkins, Docker, and Security Scanning
Utilising Terraform, Jenkins, Docker, Kubernetes and security tools to deploy Netflix clone.
## Project Overview
This project aims to leverage the principles of DevSecOps (Development, Security, and Operations) to provision a Kubernetes cluster on AWS EC2 using Terraform, and then integrate various tools and practices to ensure secure software development and deployment. The project will involve provisioning an EC2 instance, installing Kubernetes and other necessary components, setting up Jenkins for CI/CD, integrating Docker and NPM for packaging the application, implementing security scanning with Sonar, Trivy, and OWASP, and finally, deploying a Netflix clone application.

## Introduction
In the modern software development landscape, the traditional approach of siloed development, security, and operations teams has given way to a more holistic and collaborative approach known as DevSecOps. DevSecOps integrates security practices throughout the entire software development lifecycle, ensuring that security is not an afterthought but a fundamental part of the process.

By incorporating DevSecOps principles, organizations can achieve several benefits, such as:

1. **Improved Security**: Integrating security practices from the beginning helps identify and address vulnerabilities early on, reducing the risk of breaches and ensuring the overall security of the application.
2. **Faster Time-to-Market**: Automating and streamlining the development, security, and deployment processes can lead to faster delivery of software updates and new features.
3. **Increased Collaboration**: DevSecOps encourages cross-functional collaboration between development, security, and operations teams, leading to a better understanding of each other's roles and responsibilities.
4. **Reduced Costs**: Addressing security issues early in the development cycle can significantly reduce the costs associated with remediation and incident response.

In this project, we will be leveraging the following tools and technologies to implement DevSecOps practices:

1. **Terraform**: An infrastructure as code (IaC) tool that enables us to provision and manage cloud resources, such as EC2 instances, in a declarative and version-controlled manner.
2. **Jenkins**: A popular continuous integration and continuous deployment (CI/CD) tool that will help us automate the build, test, and deployment processes.
3. **Docker**: A containerisation platform that will be used to package the **Netflix clone** application and its dependencies.
4. **Kubernetes**: A container orchestration system that will be used to deploy and manage the application in a scalable and resilient manner.
5. **Sonar**: A code quality and security scanning tool that will help us identify and address code-related vulnerabilities.
6. **Trivy**: An open-source **vulnerability** scanner for container images and other artifacts that will be used to scan the Docker images.
7. **OWASP**: The Open Web Application Security Project, which provides guidance and tools for web application security, will be integrated to ensure the application's security.

By incorporating these tools and practices, we will create a secure and efficient software development and deployment pipelines, ensuring that the application is developed, tested, and deployed with a strong focus on security.

## Provisioning of resources with Terraform 
### Provisioning the EC2 Instance with Terraform
We will start by using Terraform to provision an Elastic Cloud Compute (EC2) instance with the necessary configurations, such as the Amazon Machine Image (AMI), instance type, and security group. We will also create an EBS volume and attach it to the EC2 instance for additional storage.<p>
**Configure provider.tf**:
```
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.47.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}
```
Next, we will configure the variables.tf:
```
variable "instance_type" {
  type        = list(string)
  description = "EC2 Instance type to run"
  default     = ["t2.medium", "t2.micro"]
}

variable "name" {
  type        = list(string)
  description = "Name of the instance and resources"
  default     = ["netflixclone_server", "grafana_server"]
}

variable "key_name" {
  type        = list(string)
  description = "Name of the keypair to ssh into the instance"
  default     = ["MyNTCKey", "MyGrafanaKey"]
}

variable "device_name" {
  type        = string
  description = "Name for the volume mount"
  default     = "/dev/sdf"
}

variable "volume_size" {
  type        = list(number)
  description = "Size of the volume in GB"
  default     = [30, 12]
}
```
Data.tf will import resources already provisioned in AWS to be used in our resource creation:
```
# EC2 instance data configurations
# Inport const ec2InstanceDataConfigurations:
// -------------------------------------------

# Fetch the Latest Ubuntu AMI
data "aws_ami" "ubuntu_latest" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_key_pair" "ntc-keypair" {
  key_name = "MyNTCKeypair"
}
```
Now, we we will configure the resources we want terraform to create in the main.tf file:
```
# EC2 resources for Dependecies 
resource "aws_instance" "k8s_instance" {
  ami           = data.aws_ami.ubuntu_latest.id
  instance_type = var.instance_type[0]
  key_name      = data.aws_key_pair.ntc-keypair.key_name

  user_data = <<-EOF
             #!/bin/bash
             # Update and install dependencies
             apt-get update -y
             apt-get install -y apt-transport-https ca-certificates curl software-properties-common

             # Install Docker
             curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
             add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
             apt-get update -y
             apt-get install -y docker-ce
             sudo usermod -aG docker ubuntu
             newgrp docker
             sudo chmod 777 /var/run/docker.sock

             # Install Helm
             curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash


             # Install Git
             apt-get install -y git

             EOF


  tags = {
    Name = var.name[0]
  }

  security_groups = [aws_security_group.k8s_sg.name]
}

# Security group for Netflic-clone server
resource "aws_security_group" "k8s_sg" {
  name        = "k8s-sg"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "k8s-sg"
  }
}

resource "aws_ebs_volume" "volume" {
  availability_zone = aws_instance.k8s_instance.availability_zone
  size              = var.volume_size[0]

  tags = {
    Name = "${var.name[0]}-volume"
  }
}

resource "aws_volume_attachment" "ebs_att" {
  device_name = var.device_name
  volume_id   = aws_ebs_volume.volume.id
  instance_id = aws_instance.k8s_instance.id
}

# resources for monitoring 
resource "aws_instance" "grafana_instance" {
  ami           = data.aws_ami.ubuntu_latest.id
  instance_type = var.instance_type[1]
  key_name      = data.aws_key_pair.ntc-keypair.key_name

  tags = {
    Name = "grafana-instance"
  }

  security_groups = [aws_security_group.grafana_sg.name]
}

# Security group for Grafana monitoring server
resource "aws_security_group" "grafana_sg" {
  name        = "grafana-sg"
  description = "Allow ssh inbound traffic for Grafana instance"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "grafana-sg"
  }
}

resource "aws_ebs_volume" "grafana_volume" {
  availability_zone = aws_instance.grafana_instance.availability_zone
  size              = var.volume_size[1]

  tags = {
    Name = "${var.name[1]}-volume"
  }
}

resource "aws_volume_attachment" "grafana_ebs_att" {
  device_name = var.device_name
  volume_id   = aws_ebs_volume.grafana_volume.id
  instance_id = aws_instance.grafana_instance.id
}
```
**N/B**: The user data script in the `main.tf` file will install the required dependencies, including Docker, Helm, and other tools needed to complete this project.<p>
Lastly, we will print out some details about our resources in an output.tf file:
```
output "k8s_instance_id" {
  value = aws_instance.k8s_instance.id
}
             
output "k8s_instance_public_ip" {
  value = aws_instance.k8s_instance.public_ip
}

output "grafana_instance_id" {
  value = aws_instance.grafana_instance.id
}

output "grafana_instance_public_ip" {
  value = aws_instance.grafana_instance.public_ip
}
```
**Initialise and Apply**: To provision the resource, we will run the following **Terraform** commands. 
```
terraform init                               # initialises terraform to download all the dependecies it needs to execute the build
terraform fmt                                # to format all tf files 
terraform validate                           # to ensure there are no errors in the configurations 
terraform plan --out=netflixplan             # prints out the plan of the resources to be provisioned 
terraform apply                              # applies the plan
```
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/9120e60a-6248-46ec-bb26-b6809141f4ee)<p>
**Plan Output**:
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/068bd0ce-c393-46fa-bf02-00ae3d65fe0c)<p>

Before we apply, let's ensure I do not have the EC2 instance already provisioned in the console:<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/30598ff6-be01-4051-b05e-7fac51f47fa7)<p>
Terraform has executed the plan and provisioned the resources:<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/8476cc5c-9bdd-4b0c-8e7a-fb04017a822e)<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/2534f0f8-f894-4ee6-aba3-10dcd3351144)<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/991dd49f-69c0-4bcc-9712-15d8eb266dff)<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/cdd9aed0-40d6-4830-b191-47770d23780a)<p>

#### Connecting to The Netflix Server (EC2 Instance)
Having provisioned the server, we will connect to it via ssh locally by running:
```
ssh -i "MyNTCKeyPair.pem" ubuntu@ec2-3-251-80-91.eu-west-1.compute.amazonaws.com              # Connection to the K8s-server

```
**Note**: I used the ssh client to connect:<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/732a82d1-6a99-4916-bb1e-4d8b7cdb0d25)<p>

Connection successful:<p>
![image](https://github.com/JonesKwameOsei/DevSecOps-Netflix-Clone-Deployment/assets/81886509/e6aa3800-4ece-4c8f-89f4-5c315534905a)<p>

2. **Setting up Jenkins for CI/CD**:
   - Once the EC2 instance is provisioned, we will set up Jenkins on the instance to automate the build, test, and deployment processes.
   - We will configure Jenkins to poll the GitHub repository for changes and trigger the CI/CD pipeline accordingly.
   - The pipeline will include steps for building the Docker image, running security scans, and deploying the application to the Kubernetes cluster.

3. **Integrating Docker and NPM for Packaging the Application**:
   - We will use Docker to package the Netflix clone application and its dependencies into a containerized environment.
   - The application's source code will be built using NPM, and the resulting artifacts will be bundled into a Docker image.
   - The Docker image will be pushed to a container registry, such as Amazon Elastic Container Registry (ECR) or Docker Hub, for deployment.

4. **Implementing Security Scanning**:
   - We will integrate Sonar to perform code quality and security analysis on the application's source code.
   - Trivy will be used to scan the Docker images for known vulnerabilities, ensuring that the deployed containers are secure.
   - OWASP will be integrated to assess the application's security posture and identify any potential web application vulnerabilities.

5. **Deploying the Application to Kubernetes**:
   - The Jenkins pipeline will deploy the application to the Kubernetes cluster provisioned by Terraform.
   - We will use Helm, a package manager for Kubernetes, to simplify the deployment and management of the application and its dependencies, including Prometheus and Grafana for monitoring.
   - The Kubernetes resources, such as Deployments, Services, and Ingress, will be defined and managed using Terraform.

6. **Monitoring and Observability**:
   - Prometheus and Grafana will be installed and configured to provide comprehensive monitoring and observability for the Kubernetes cluster and the deployed application.
   - The Grafana dashboard will be set up to visualize key metrics and performance indicators, enabling the team to quickly identify and address any issues.

7. **Cleanup and Destruction of Resources**:
   - After the successful deployment and testing of the application, we will use Terraform to destroy all the provisioned resources, including the EC2 instance, EBS volume, and Kubernetes cluster.
   - This ensures that we don't incur unnecessary costs for resources that are no longer needed.

## Conclusion
By completing this DevSecOps project, I have gained valuable experience in integrating security practices throughout the software development lifecycle. I have learned how to:

1. Provision infrastructure using Terraform as code, ensuring consistency and repeatability.
2. Set up a CI/CD pipeline with Jenkins, automating the build, test, and deployment processes.
3. Package the application using Docker and manage the deployment with Kubernetes.
4. Implement security scanning tools like Sonar, Trivy, and OWASP to identify and address vulnerabilities early on.
5. Set up monitoring and observability with Prometheus and Grafana, enabling better visibility and proactive issue resolution.
6. Effectively manage the entire lifecycle of the infrastructure and application, including cleanup and destruction of resources.

This project has strengthened my understanding of DevSecOps principles and the importance of integrating security throughout the software development process. The skills and knowledge I have gained will be invaluable in my future endeavors, as I continue to build secure and robust applications that meet the evolving security requirements of the modern software landscape.
