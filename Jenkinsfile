import java.util.regex.Pattern
import org.jenkinsci.plugins.pipeline.modeldefinition.Utils

podTemplate(label: 'k8skeycloak-controller',
  containers: [
    containerTemplate(
      name: 'golang',
      image: 'bitnami/golang:1.15',
      ttyEnabled: true
    ),
    containerTemplate(
      name: 'kaniko',
      command: '/busybox/cat',
      image: 'gcr.io/kaniko-project/executor:debug',
      ttyEnabled: true
    ),
    containerTemplate(
      name: 'helm',
      command: '/bin/ash',
      image: 'alpine/helm:latest',
      ttyEnabled: true
    ),
  ],
  volumes: [
    secretVolume(secretName: 'dockerauth', mountPath: '/root/dockerauth')
  ]
) {
  node ('k8skeycloak-controller') {
    ansiColor("xterm") {
      stage('checkout') {
        checkout(scm)
      }

      stage("build") {
        container('golang') {
          sh 'make all'
        }

        container('helm') {
          sh 'helm lint chart/k8skeycloak-controller'
        }
      }

      stage("publish") {
        if (!env.TAG_NAME) {
          echo "skip packaging for no tagged release"
        } else {
          def (_,major,minor,patch,group,label,build) = (env.TAG_NAME =~ /^v(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:(-([A-Za-z0-9]+)))?$/)[0]

          if (!major && !minor && !patch) {
            throw new Exception("Invalid tag detected, requires semantic version")
          }

          version = "$major.$minor.$patch$group"

          container(name: 'kaniko', shell: '/busybox/sh') {
            sh "cp /root/dockerauth/.dockerconfigjson /kaniko/.docker/config.json"
            sh "/kaniko/executor -f `pwd`/Dockerfile -c `pwd` --destination='nexus.doodle.com:5000/devops/k8skeycloak-controller:${env.TAG_NAME}'"
          }

          container('helm') {
            bumpChartVersion(version)
            bumpImageVersion(env.TAG_NAME)

            tgz="k8skeycloak-controller-${version}.tgz"
            sh "mkdir chart/k8skeycloak-controller/crds"
            sh "cp config/crd/bases/* chart/k8skeycloak-controller/crds"
            sh "helm package chart/k8skeycloak-controller"
          }

          container('golang') {
            if (label) {
              publish(tgz, "helm-staging")
            } else {
              publish(tgz, "helm-staging")
              publish(tgz, "helm-production")
            }
          }
        }
      }
    }
  }
}

def bumpImageVersion(String version) {
  echo "Update image tag"
  def valuesFile = "./chart/k8skeycloak-controller/values.yaml"
  def valuesData = readYaml file: valuesFile
  valuesData.image.tag = version

  sh "rm $valuesFile"
  writeYaml file: valuesFile, data: valuesData
}

def bumpChartVersion(String version) {
  // Bump chart version
  echo "Update chart version"
  def chartFile = "./chart/k8skeycloak-controller/Chart.yaml"
  def chartData = readYaml file: chartFile
  chartData.version = version
  chartData.appVersion = version

  sh "rm $chartFile"
  writeYaml file: chartFile, data: chartData
}

def publish(String tgz, String repository) {
  echo "Push chart ${tgz} to helm repository ${repository}"

  withCredentials([[
    $class          : 'UsernamePasswordMultiBinding',
    credentialsId   : 'nexus',
    usernameVariable: 'NEXUS_USER',
    passwordVariable: 'NEXUS_PASSWORD'
  ]]) {
    sh "curl -u \"${env.NEXUS_USER}:${env.NEXUS_PASSWORD}\" https://nexus.doodle.com/repository/${repository}/ --upload-file $tgz --fail"
  }
}
