# main.tf

# Эмуляция security group правил через locals
locals {
  security_rules = [
    {
      name     = "insecure_ssh"
      port     = 22
      cidr     = "0.0.0.0/0"
      protocol = "tcp"
    },
    {
      name     = "insecure_rdp" 
      port     = 3389
      cidr     = "0.0.0.0/0"
      protocol = "tcp"
    },
    {
      name     = "secure_web"
      port     = 443
      cidr     = "10.0.0.0/16" # Private CIDR - безопасно
      protocol = "tcp"
    }
  ]
  
  storage_configs = [
    {
      name      = "unencrypted_disk"
      encrypted = false
    },
    {
      name      = "encrypted_disk"
      encrypted = true
    }
  ]
}

# Ресурсы для демонстрации
resource "null_resource" "insecure_sg_ssh" {
  triggers = {
    rule = jsonencode(local.security_rules[0])
  }
}

resource "null_resource" "insecure_sg_rdp" {
  triggers = {
    rule = jsonencode(local.security_rules[1])
  }
}

resource "null_resource" "secure_sg_web" {
  triggers = {
    rule = jsonencode(local.security_rules[2])
  }
}

resource "null_resource" "unencrypted_disk" {
  triggers = {
    config = jsonencode(local.storage_configs[0])
  }
}

resource "null_resource" "encrypted_disk" {
  triggers = {
    config = jsonencode(local.storage_configs[1])
  }
}