provider "azurerm" {
  features { }
}

resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_app_service_plan" "example" {
  name                = "example-appserviceplan"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  sku {
    tier = "Standard"
    size = "S1"
  }
}

### azurerm_app_service ###
resource "azurerm_app_service" "example" {
# $.resource.*.azurerm_app_service[*].*[*].identity anyNull
  name                = "example-app-service"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  app_service_plan_id = azurerm_app_service_plan.example.id
# $.resource[*].azurerm_app_service.*.*.* size > 0 and ($.resource[*].azurerm_app_service[*].*.*.https_only anyNull or $.resource[*].azurerm_app_service[*].*.*.https_only anyFalse)
  https_only = false
# $.resource[*].azurerm_app_service exists and ($.resource[*].azurerm_app_service[*].*.*.client_cert_enabled anyNull or $.resource[*].azurerm_app_service[*].*.*.client_cert_enabled anyFalse)
  client_cert_enabled = false
# $.resource[*].azurerm_app_service.*.*.* size > 0 and ($.resource[*].azurerm_app_service[*].*.*.http2_enabled anyNull or $.resource[*].azurerm_app_service[*].*.*.http2_enabled anyFalse)
# $.resource.*.azurerm_app_service[*].*[*].site_config[?( @.dotnet_framework_version !='v4.0' && @.dotnet_framework_version )] size greater than 0
# $.resource.*.azurerm_app_service[*].*[*].site_config[?(  @.min_tls_version!='1.2' && @.min_tls_version )] size greater than 0
  site_config {
    http2_enabled = false
    dotnet_framework_version = "v2.0"
    scm_type                 = "LocalGit"
    min_tls_version = "1.0"
  }

  app_settings = {
    "SOME_KEY" = "some-value"
  }

  connection_string {
    name  = "Database"
    type  = "SQLServer"
    value = "Server=some-server.mydomain.com;Integrated Security=SSPI"
  }

# $.resource.*.azurerm_app_service[*].*[*].identity anyNull

# $.resource.*.azurerm_app_service[*].*[*].auth_settings[*].enabled anyFalse or $.resource.*.azurerm_app_service[*].*[*].auth_settings anyNull
  auth_settings {
    enabled = "false"
    active_directory {
      client_id = "3"
    }
    default_provider = "AzureActiveDirectory"
  }  
}

data "azurerm_client_config" "current" {
}
resource "azurerm_key_vault" "example" {
  name                = "name"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id

  sku_name = "premium"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "create",
      "get",
    ]

    secret_permissions = [
      "set",
      "get",
      "delete",
    ]
  }

  tags = {
    environment = "Production"
  }
}

### azurerm_key_vault_secret ###
# $.resource.*.azurerm_key_vault_secret[*].*[*].expiration_date anyNull
resource "azurerm_key_vault_secret" "example" {
  name         = "secret-sauce"
  value        = "szechuan"
  key_vault_id = azurerm_key_vault.example.id
}

### azurerm_network_security_group ###
resource "azurerm_network_security_group" "example" {
  name                = "acceptanceTestSecurityGroup1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}

# ($.resource[*].azurerm_network_security_rule exists and ($.resource[*].azurerm_network_security_rule.*[*].*.access contains Allow and $.resource[*].azurerm_network_security_rule.*[*].*.destination_address_prefix contains * and $.resource[*].azurerm_network_security_rule.*[*].*.source_address_prefix contains * and $.resource[*].azurerm_network_security_rule.*[*].*.destination_port_range contains 22 and $.resource[*].azurerm_network_security_rule.*[*].*.direction contains Inbound))
resource "azurerm_network_security_rule" "example" {
  name                        = "test123"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
}
# ($.resource.*.azurerm_network_security_rule[*].*[?( @.access == 'Allow' && @.direction == 'Inbound' )].destination_port_ranges contains 3389 or $.resource.*.azurerm_network_security_rule[*].*[?( @.access == 'Allow' && @.direction == 'Inbound' )].destination_port_range equals 3389) or ($.resource.*.azurerm_network_security_group[*].*[*].security_rule[?( @.access == 'Allow' && @.direction == 'Inbound' )].destination_port_ranges contains 3389 or $.resource.*.azurerm_network_security_group[*].*[*].security_rule[?( @.access == 'Allow' && @.direction == 'Inbound' )].destination_port_range equals 3389)
resource "azurerm_network_security_rule" "example2" {
  name                        = "test123"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.example.name
  network_security_group_name = azurerm_network_security_group.example.name
}
resource "azurerm_network_watcher" "example" {
  name                = "acctestnw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
}
# $.resource[*].azurerm_storage_account exists and ($.resource[*].azurerm_storage_account.*[*].*.enable_https_traffic_only anyNull or $.resource[*].azurerm_storage_account.*[*].*.enable_https_traffic_only anyFalse)
# $.resource.*.azurerm_storage_account size greater than 0 and ($.resource.*.azurerm_storage_account[*].*[*].network_rules anyNull or $.resource.*.azurerm_storage_account[*].*[*].network_rules[*].bypass anyNull or not ( $.resource.*.azurerm_storage_account[*].*[*].network_rules[*].bypass allEqual "AzureServices" ))
# $.resource.*.azurerm_storage_account.*.*.*.queue_properties.*.logging.* size > 0 and ($.resource.*.azurerm_storage_account.*.*.*.queue_properties.*.logging.*.delete anyFalse or $.resource.*.azurerm_storage_account.*.*.*.queue_properties.*.logging.*.read anyFalse or $.resource.*.azurerm_storage_account.*.*.*.queue_properties.*.logging.*.write anyFalse )
resource "azurerm_storage_account" "example" {
  name                = "acctestsa"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  account_tier              = "Standard"
  account_kind              = "StorageV2"
  account_replication_type  = "LRS"
  enable_https_traffic_only = false
  queue_properties {
    logging {
      delete = true
      read = true
      write = false
      version = 1.0
    }
  }
  network_rules {
    default_action             = "Allow"
    bypass = ["None"]
    ip_rules                   = ["30.0.0.1/16"]
  }
}
# $.resource.*.azurerm_storage_blob size greater than 0 and $.resource.*.azurerm_storage_container size greater than 0 and $.resource.*.azurerm_storage_container[*].*.[*].container_access_type anyEqual blob or $.resource.*.azurerm_storage_container[*].*.[*].container_access_type anyEqual container
resource "azurerm_storage_container" "example" {
  name                  = "content"
  storage_account_name  = azurerm_storage_account.example.name
  container_access_type = "blob"
}
resource "azurerm_storage_blob" "example" {
  name                   = "my-awesome-content.zip"
  storage_account_name   = azurerm_storage_account.example.name
  storage_container_name = azurerm_storage_container.example.name
  type                   = "Block"
  source                 = "some-local-file.zip"
}
resource "azurerm_log_analytics_workspace" "example" {
  name                = "acctestlaw"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "PerGB2018"
}
# $.resource.*.azurerm_network_security_group size greater than 0 and ($.resource.*.azurerm_network_watcher_flow_log size equals 0 or $.resource.*.azurerm_network_watcher_flow_log[*].*[*].enabled anyNull or $.resource.*.azurerm_network_watcher_flow_log[*].*[*].enabled anyFalse or $.resource.*.azurerm_network_watcher_flow_log[*].*[*].retention_policy[*].enabled anyFalse or $.resource.*.azurerm_network_watcher_flow_log[*].*[*].retention_policy[?( @.days<90 )] size greater than 0)
resource "azurerm_network_watcher_flow_log" "example" {
  network_watcher_name = azurerm_network_watcher.example.name
  resource_group_name  = azurerm_resource_group.example.name
  network_security_group_id = azurerm_network_security_group.example.id
  storage_account_id        = azurerm_storage_account.example.id
  enabled                   = true
  retention_policy {
    enabled = true
    days    = 9
  }
  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.example.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.example.location
    workspace_resource_id = azurerm_log_analytics_workspace.example.id
    interval_in_minutes   = 10
  }
}
### azurerm_virtual_machine ###
resource "azurerm_virtual_machine" "example" {
  name                  = "acctvm"
  location              = azurerm_resource_group.example.location
  resource_group_name   = azurerm_resource_group.example.name
  network_interface_ids = [azurerm_network_security_group.example.id]
  vm_size               = "Standard_F2"
  storage_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "16.04-LTS"
    version   = "latest"
  }
  storage_os_disk {
    name          = "myosdisk1"
    vhd_uri       = "foo/myosdisk1.vhd"
    caching       = "ReadWrite"
    create_option = "FromImage"
  }
  os_profile {
    computer_name  = "hostname"
    admin_username = "testadmin"
    admin_password = "Password1234!"
  }
  os_profile_linux_config {
    disable_password_authentication = false
  }
  tags = {
    environment = "staging"
  }
}
# $.resource.*.azurerm_virtual_machine size greater than 0 and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain EndpointSecurity and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain TrendMicroDSA and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain Antimalware and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain EndpointProtection and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain SCWPAgent and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain PortalProtectExtension and $.resource.*.azurerm_virtual_machine_extension[*].*[*].type does not contain FileSecurity
resource "azurerm_virtual_machine_extension" "example" {
  name                 = "hostname"
  virtual_machine_id   = azurerm_virtual_machine.example.id
  publisher            = "Microsoft.Azure.Extensions"
  type                 = "CustomScript"
  type_handler_version = "2.0"
  settings = <<SETTINGS
    {
        "commandToExecute": "hostname && uptime"
    }
SETTINGS
  tags = {
    environment = "Production"
  }
}
### azurerm_sql_server ###
resource "azurerm_sql_server" "example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "mradministrator"
  administrator_login_password = "thisIsDog11"

  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }

  tags = {
    environment = "production"
  }
}
#  $.resource.*.azurerm_sql_server size greater than 0 and ($.resource.*.azurerm_sql_active_directory_administrator size equals 0)
# $.resource.*.azurerm_sql_server size greater than 0 and ($.resource.*.azurerm_mssql_server_security_alert_policy size == 0 or  $.resource.*.azurerm_mssql_server_security_alert_policy[*].*[*].state anyEqual "Disabled" or $.resource.*.azurerm_mssql_server_security_alert_policy[*].*[*].retention_days anyNull )
resource "azurerm_mssql_server_security_alert_policy" "example" {
  resource_group_name        = azurerm_resource_group.example.name
  server_name                = azurerm_sql_server.example.name
  state                      = "Disabled"
  storage_endpoint           = azurerm_storage_account.example.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.example.primary_access_key
  disabled_alerts = [
    "Sql_Injection",
    "Data_Exfiltration"
  ]
  retention_days = 20
}

### azurerm_sql_database ###
# $.resource.*.azurerm_sql_database size greater than 0 and $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy size greater than 0 and $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].disabled_alerts[*] size greater than 0
# $.resource.*.azurerm_sql_database size greater than 0 and ($.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy anyNull or $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].state anyEqual Disabled)
# $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy anyNull or $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].state anyEqual Disabled or $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].email_account_admins  anyNull or $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].email_account_admins anyFalse
# $.resource.*.azurerm_sql_database size greater than 0 and $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy size greater than 0 and ($.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[*].retention_days anyNull or $.resource.*.azurerm_sql_database[*].*[*].threat_detection_policy[?( @.retention_days<91 )] size greater than 0)
resource "azurerm_sql_database" "example" {
  name                = "myexamplesqldatabase"
  resource_group_name = azurerm_resource_group.example.name
  location            = "West US"
  server_name         = azurerm_sql_server.example.name
  threat_detection_policy {
    state = "Disabled"
    email_account_admins = "Disabled"
    retention_days = 90
    disabled_alerts = ["Access_Anomaly"]
  }
  extended_auditing_policy {
    storage_endpoint                        = azurerm_storage_account.example.primary_blob_endpoint
    storage_account_access_key              = azurerm_storage_account.example.primary_access_key
    storage_account_access_key_is_secondary = true
    retention_in_days                       = 6
  }
  tags = {
    environment = "production"
  }
}
### azurerm_monitor_log_profile ###
# $.resource.*.azurerm_monitor_log_profile size greater than 0 and ( $.resource.*.azurerm_monitor_log_profile[*].*[*].retention_policy size equals 0 or $.resource.*.azurerm_monitor_log_profile[*].*[*].retention_policy[*].enabled anyFalse or $.resource.*.azurerm_monitor_log_profile[*].*[*].retention_policy[?(@.days<365)] size greater than 0 )
resource "azurerm_monitor_log_profile" "example" {
  name = "default"
  categories = [
    "Action",
    "Delete",
    "Write",
  ]
  locations = [
    "westus",
    "global",
  ]
  # RootManageSharedAccessKey is created by default with listen, send, manage permissions
  # servicebus_rule_id = "${azurerm_eventhub_namespace.example.id}/authorizationrules/RootManageSharedAccessKey"
  # storage_account_id = azurerm_storage_account.example.id
  retention_policy {
    enabled = true
    days    = 7
  }
}

### azurerm_kubernetes_cluster ###
# $.resource.*.azurerm_kubernetes_cluster[*].*[*].role_based_access_control anyNull or $.resource.*.azurerm_kubernetes_cluster[*].*[*].role_based_access_control[*].enabled anyFalse
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks1"
  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  role_based_access_control {
    enabled = false
  }
}