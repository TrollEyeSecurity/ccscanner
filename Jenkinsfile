pipeline {
    agent  {
        label "production"
    }
    environment {
        TOKEN = credentials('fury-io-token')
      }
    stages {
        stage("Build and push dpkg") {
            agent  {
                label "ubuntu"
            }
            steps {
                script {
                    sh "make build_dpkg"
                    sh "curl -F package=@ccscanner_2.0.4-0ubuntu_amd64.deb https://$TOKEN@push.fury.io/trolleyesecurity/"
                }
            }
        }
        stage("Clean up") {
            steps {
                script {
                    sh "rm -rf *"
                }
            }
        }
    }
}