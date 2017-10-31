# (c) Copyright 2016-2017 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

require 'rspec'
require 'spec_helper'

describe HPE3PARClient::Client do
  before(:all) do
    @api_hash = {'major' => 1, 'minor' => 6, 'revision' => 0, 'build' => 30_102_612}
    @api_unsupported_hash = {'major' => 1, 'minor' => 5, 'revision' => 0, 'build' => 30_102_612}
    @url = 'https://1.1.1.1/api/v1'
  end

  after(:all) do
    @api_hash = nil
    @url = nil
  end
  
  app_type = 'ruby-3parclient'
  ssh = nil

  it 'Validate login' do
    session_key = 'ABCDEF'
    user = 'my_user'
    password = 'mypassword'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow(http).to receive(:authenticate).and_return(session_key)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    ci = HPE3PARClient::Client.new(@url)
    ci.instance_variable_set('@http', http)
    expect(ci.login(user, password)).to eq(session_key)
  end

  it 'Validate logout' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow(http).to receive(:unauthenticate)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    ci = HPE3PARClient::Client.new(@url)
    ci.instance_variable_set('@http', http)
    expect(ci.logout)
  end

  it 'validate get vluns' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vlun_obj = HPE3PARClient::VlunManager.new(http, true)
    client.instance_variable_set('@vlun', vlun_obj)
    allow(vlun_obj).to receive(:get_vluns).and_return(nil)
    expect(client.get_vluns).to eq(nil)
  end

  it 'validate get vlun' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vlun_obj = HPE3PARClient::VlunManager.new(http, true)
    client.instance_variable_set('@vlun', vlun_obj)
    allow(vlun_obj).to receive(:get_vlun).with('volume').and_return(nil)
    expect(client.get_vlun('volume')).to eq(nil)
  end

  it 'validate create vlun' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vlun_obj = HPE3PARClient::VlunManager.new(http, true)
    client.instance_variable_set('@vlun', vlun_obj)
    allow(vlun_obj).to receive(:create_vlun).with('volume', nil, nil, nil, nil, nil, false).and_return(nil)
    expect(client.create_vlun('volume', nil, nil, nil, nil, nil, false)).to eq(nil)
  end

  it 'validate delete vlun' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vlun_obj = HPE3PARClient::VlunManager.new(http, true)
    client.instance_variable_set('@vlun', vlun_obj)
    allow(vlun_obj).to receive(:delete_vlun).with('volume_name', 2, 'host_name', nil).and_return(nil)
    expect(client.delete_vlun('volume_name', 2, 'host_name')).to eq(nil)
  end

  it 'validate query qos rules' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:query_qos_rules).and_return(nil)
    expect(client.query_qos_rules).to eq(nil)
  end

  it 'validate query qos rule' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:query_qos_rule).with('target_name', 'vvset').and_return(nil)
    expect(client.query_qos_rule('target_name')).to eq(nil)
  end

  it 'validate create qos rule' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_rules = {}
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:create_qos_rules).with('target_name', qos_rules, 'vvset').and_return(nil)
    expect(client.create_qos_rules('target_name', qos_rules, 'vvset')).to eq(nil)
  end

  it 'validate create qos rule with the muliple versions' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    api_hash = {'major' => 1, 'minor' => 5, 'revision' => 3, 'build' => 30_102_612}
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version).and_return(@api_hash)
    client = HPE3PARClient::Client.new(@url)
    qos_rules = {'latencyGoaluSecs' => 1}
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@api_version', api_hash)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:create_qos_rules).with('target_name', qos_rules, 'vvset').and_return(nil)
    expect(client.create_qos_rules('target_name', qos_rules, 'vvset')).to eq(nil)
  end

  it 'validate modify qos rule' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_rules = {}
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:modify_qos_rules).with('target_name', qos_rules, 'vvset').and_return(nil)
    expect(client.modify_qos_rules('target_name', qos_rules, 'vvset')).to eq(nil)
  end

  it 'validate modify qos rule with multiple versions' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    api_hash = {'major' => 1, 'minor' => 5, 'revision' => 3, 'build' => 30_102_612}
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_rules = {}
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@api_version', api_hash)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:modify_qos_rules).with('target_name', qos_rules, 'vvset').and_return(nil)
    expect(client.modify_qos_rules('target_name', qos_rules, 'vvset')).to eq(nil)
  end

  it 'validate delete qos rule' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    qos_obj = HPE3PARClient::QOSManager.new(http)
    client.instance_variable_set('@qos', qos_obj)
    allow(qos_obj).to receive(:delete_qos_rules).with('target_name', 'vvset').and_return(nil)
    expect(client.delete_qos_rules('target_name')).to eq(nil)
  end

  it 'validate get all hosts' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/hosts.json')
    all_hosts = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:get_hosts).and_return(all_hosts)
    expect(client.get_hosts).to eq(all_hosts)
  end

  it 'validate get a host' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/host.json')
    host = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:get_host).with('host').and_return(host)
    expect(client.get_host('host')).to eq(host)
  end

  it 'validate create a host' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:create_host).with('name', nil, nil, nil).and_return(nil)
    expect(client.create_host('name')).to eq(nil)
  end

  it 'validate modify a host' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:modify_host).with('name', 'mod_req').and_return(nil)
    expect(client.modify_host('name', 'mod_req')).to eq(nil)
  end

  it 'validate delete host' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:delete_host).with('name').and_return(nil)
    expect(client.delete_host('name')).to eq(nil)
  end

  it 'validate querying a host by fc path' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:query_host_by_fc_path).and_return(nil)
    expect(client.query_host_by_fc_path(nil)).to eq(nil)
  end

  it 'validate querying a host by iscsi path' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:query_host_by_iscsi_path).and_return(nil)
    expect(client.query_host_by_iscsi_path(nil)).to eq(nil)
  end

  it 'validate get host vluns' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_obj = HPE3PARClient::HostManager.new(http)
    client.instance_variable_set('@host', host_obj)
    allow(host_obj).to receive(:get_host_vluns).with('host_name').and_return(nil)
    expect(client.get_host_vluns('host_name')).to eq(nil)
  end

  it 'validate get all hostsets' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/hostsets.json')
    all_host_sets = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:get_host_sets).and_return(all_host_sets)
    expect(client.get_host_sets).to eq(all_host_sets)
  end

  it 'validate get a hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/hostset.json')
    host_set = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:get_host_set).with('host_set_name').and_return(host_set)
    expect(client.get_host_set('host_set_name')).to eq(host_set)
  end

  it 'validate create hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:create_host_set).with('host_set_name', nil, nil, nil).and_return(nil)
    expect(client.create_host_set('host_set_name')).to eq(nil)
  end

  it 'validate delete hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:delete_host_set).with('host_set_name').and_return(nil)
    expect(client.delete_host_set('host_set_name')).to eq(nil)
  end

  it 'validate modify hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:modify_host_set).with('host_set_name', nil, nil, nil, nil).and_return(nil)
    expect(client.modify_host_set('host_set_name')).to eq(nil)
  end

  it 'validate add host to hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:add_hosts_to_host_set).with('host_set_name', ['host_name']).and_return(nil)
    expect(client.add_hosts_to_host_set('host_set_name', ['host_name'])).to eq(nil)
  end

  it 'validate remove host from hostset' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:remove_hosts_from_host_set).with('host_set_name', ['host_name']).and_return(nil)
    expect(client.remove_hosts_from_host_set('host_set_name', ['host_name'])).to eq(nil)
  end

  it 'validate find all host sets of a particular host' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    host_set_obj = HPE3PARClient::HostSetManager.new(http)
    client.instance_variable_set('@host_set', host_set_obj)
    allow(host_set_obj).to receive(:find_host_sets).with('host_name').and_return(nil)
    expect(client.find_host_sets('host_name')).to eq(nil)
  end

  it 'should get storage system info' do
    file = File.read('spec/json/storageinfo.json')
    storage_info = JSON.parse(file)
    return_body = nil, storage_info
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow(http).to receive(:get).with('/system').and_return(return_body)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    client.instance_variable_set('@http', http)
    expect(client.get_storage_system_info).to eq(storage_info)
  end

  it 'should get Overall SystemCapacity' do
    file = File.read('spec/json/overall_storage_capacity.json')
    capacity_info = JSON.parse(file)
    return_body = nil, capacity_info
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow(http).to receive(:get).with('/capacity').and_return(return_body)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    client.instance_variable_set('@http', http)
    expect(client.get_overall_system_capacity).to eq(capacity_info)
  end

  it 'should get WSAPIConfiguration Info' do
    wsapi_config_info = {'httpState' => 'Enabled', 'httpPort' => 8008, 'httpsState' => 'Enabled', 'httpsPort' => 8080, 'version' => '1.5.3', 'sessionsInUse' => 18, 'systemResourceUsage' => 108, 'sessionTimeout' => 15}
    return_body = nil, wsapi_config_info
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow(http).to receive(:get).with('/wsapiconfiguration').and_return(return_body)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    client.instance_variable_set('@http', http)
    expect(client.get_ws_api_configuration_info).to eq(wsapi_config_info)
  end

  it 'validate get all tasks' do
    file = File.read('spec/json/tasks.json')
    task_info = JSON.parse(file)
    return_body = [nil, task_info]
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    allow(http).to receive(:get).with('/tasks').and_return(return_body)
    client = HPE3PARClient::Client.new(@url)
    task = HPE3PARClient::TaskManager.new(http)
    client.instance_variable_set('@task', task)
    out = client.get_all_tasks
    expect(out.size).to eq(2)
  end

  it 'validate get task by id' do
    task_id = 1
    file = File.read('spec/json/tasks.json')
    task_info = JSON.parse(file)
    tasks_output = task_info['members'].find {|t| t['id'] == task_id}
    return_body = [nil, tasks_output]
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    allow(http).to receive(:get).with("/tasks/#{task_id}").and_return(return_body)
    client = HPE3PARClient::Client.new(@url)
    task_manager = HPE3PARClient::TaskManager.new(http)
    client.instance_variable_set('@task', task_manager)
    task = client.get_task(task_id)
    expect(task.task_id).to eq(task_id)
  end


  it 'validate create flash cache' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    fc_obj = HPE3PARClient::FlashCacheManager.new(http)
    client.instance_variable_set('@flash_cache', fc_obj)
    allow(fc_obj).to receive(:create_flash_cache).with(64, 1)
    expect(client.create_flash_cache(64, 1))
  end

  it 'validate get flash cache' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    flash_cache_output = {'mode' => 1, 'sizeGiB' => 128, 'state' => 1,
                          'usedSizeGiB' => 0,
                          'links' => [{'href' => 'https://15.212.192.252:8080/api/v1/flashcache',
                                       'rel' => 'self'}]}
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    fc_obj = HPE3PARClient::FlashCacheManager.new(http)
    client.instance_variable_set('@flash_cache', fc_obj)
    allow(fc_obj).to receive(:get_flash_cache).and_return(flash_cache_output)
    expect(client.get_flash_cache).to eq(flash_cache_output)
  end

  it 'validate delete flash cache' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    fc_obj = HPE3PARClient::FlashCacheManager.new(http)
    client.instance_variable_set('@flash_cache', fc_obj)
    allow(fc_obj).to receive(:delete_flash_cache)
    expect(client.delete_flash_cache)
  end

  it 'validate get all volumes' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/volumes.json')
    all_volumes = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volumes).and_return(all_volumes)
    expect(client.get_volumes).to eq(all_volumes)
  end

  it 'validate get all snapshots' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/snapshots.json')
    all_volumes = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volumes).and_return(all_volumes)
    expect(client.get_snapshots).to eq(all_volumes)
  end

  it 'validate get volume' do
    volume_name = 'vvr_2'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/volume.json')
    volume_response = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volume).with(volume_name).and_return(volume_response)
    expect(client.get_volume(volume_name)).to eq(volume_response)
  end

  it 'validate get volume by wwn' do
    volume_wwn = '60002AC000000000000001500000B69E'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/volume.json')
    volume_response = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volume_by_wwn).with(volume_wwn).and_return(volume_response)
    expect(client.get_volume_by_wwn(volume_wwn)).to eq(volume_response)
  end

  it 'validate create volume' do
    volume_name = 'vvr_2'
    cpg_name = 'cpg_test'
    size = 1024
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:create_volume).and_return(nil)
    expect(client.create_volume(volume_name, cpg_name, size)).to eq(nil)
  end

  it 'validate delete volume' do
    volume_name = 'vvr_2'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:delete_volume).and_return(nil)
    expect(client.delete_volume(volume_name)).to eq(nil)
  end

  it 'validate modify volume' do
    volume_name = 'vvr_2'
    new_volume_name = 'vvr_3'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:modify_volume).and_return(nil)
    expect(client.modify_volume(volume_name,
                                'newName' => new_volume_name)).to eq(nil)
  end

  it 'validate grow volume' do
    volume_name = 'vvr_2'
    grow_amount = 1024
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:grow_volume).and_return(nil)
    expect(client.grow_volume(volume_name, grow_amount)).to eq(nil)
  end

  it 'validate copy volume' do
    volume_name = 'vvr_2'
    copy_volume_name = 'vvr_3'
    destination_cpg = 'destCPG'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:create_physical_copy).and_return(nil)
    expect(client.create_physical_copy(volume_name, copy_volume_name, destination_cpg)).to eq(nil)
  end

  it 'validate tune volume' do
    volume_name = 'vvr_2'
    tune_operation = 1
    new_cpg = 'FC_r1'
    optional =  {'userCPG' => new_cpg}
    task = {'id' =>1, 'type' =>15, 'name' => 'check_slow_disk', 'status' =>1,
            'startTime' => '2017-08-02 02:07:00 PDT', 'finishTime' => '2017-08-02 03:03:01 PDT', 'user' => '3parsvc'}
    tune_response = {'taskid' => 1234 }
    return_body = nil, tune_response
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    allow(http).to receive(:put).and_return(return_body)
    allow(http).to receive(:get).and_return([nil, task])
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    allow(vol_obj).to receive(:tune_volume).and_return(tune_response)
    client.instance_variable_set('@volume', vol_obj)

    task_manager = HPE3PARClient::TaskManager.new(http)
    client.instance_variable_set('@task', task_manager)

    task = client.tune_volume(volume_name, tune_operation, optional)
    expect(task.task_id).to eq(1)
  end


  it 'validate get all volumesets' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/volumesets.json')
    all_volumesets = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:get_volume_sets).and_return(all_volumesets)
    expect(client.get_volume_sets).to eq(all_volumesets)
  end

  it 'validate get volumeset' do
    volume_set_name = 'C20DUM1'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/volumeset.json')
    volume_set_response = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:get_volume_set).with(volume_set_name).and_return(volume_set_response)
    expect(client.get_volume_set(volume_set_name)).to eq(volume_set_response)
  end

  it 'validate create volumeset' do
    volume_set_name = 'C20DUM1'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:create_volume_set).and_return(nil)
    expect(client.create_volume_set(volume_set_name)).to eq(nil)
  end

  it 'validate modify volumeset' do
    volume_set_name = 'C20DUM1'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:modify_volume_set).and_return(expected_response)
    expect(client.modify_volume_set(volume_set_name)).to eq(expected_response)
  end

  it 'validate delete volumeset' do
    volume_set_name = 'C20DUM1'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:delete_volume_set).and_return(expected_response)
    expect(client.delete_volume_set(volume_set_name)).to eq(expected_response)
  end

  it 'validate add volume to volumeset' do
    volume_set_name = 'C20DUM1'
    setmembers = ['vvr_2']
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:add_volumes_to_volume_set).and_return(expected_response)
    expect(client.add_volumes_to_volume_set(volume_set_name, setmembers)).to eq(expected_response)
  end

  it 'validate remove volume from volumeset' do
    volume_set_name = 'C20DUM1'
    setmembers = ['vvr_2']
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:remove_volumes_from_volume_set).and_return(expected_response)
    expect(client.remove_volumes_from_volume_set(volume_set_name, setmembers)).to eq(expected_response)
  end

  it 'validate find all volume sets' do
    volume_name = 'vvr_2'
    file = File.read('spec/json/volumeset.json')
    data_hash = JSON.parse(file)
    response = 'sample_response'
    reponse_and_body = response, data_hash
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_set_obj = HPE3PARClient::VolumeSetManager.new(http)
    client.instance_variable_set('@volume_set', vol_set_obj)
    allow(vol_set_obj).to receive(:find_all_volume_sets).and_return(reponse_and_body[1])
    expect(client.find_all_volume_sets(volume_name)).to eq(reponse_and_body[1])
  end

  it 'validate create snapshot' do
    volume_name = 'parent_volume'
    snapshot_name = 'child_volume'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:create_snapshot).and_return(expected_response)
    expect(client.create_snapshot(snapshot_name, volume_name)).to eq(expected_response)
  end

  it 'validate restore snapshot' do
    snapshot_name = 'child_volume'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:restore_snapshot).and_return(expected_response)
    expect(client.restore_snapshot(snapshot_name)).to eq(expected_response)
  end

  it 'validate delete snapshot' do
    snapshot_name = 'child_volume'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:delete_volume).and_return(expected_response)
    expect(client.delete_snapshot(snapshot_name)).to eq(expected_response)
  end

  it 'validate get volume snapshot' do
    volume_name = 'parent_volume'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volume_snapshots).and_return(expected_response)
    expect(client.get_volume_snapshots(volume_name)).to eq(expected_response)
  end

  it 'validate get all cpgs' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/cpgs.json')
    all_cpgs = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:get_cpgs).and_return(all_cpgs)
    expect(client.get_cpgs).to eq(all_cpgs)
  end

  it 'validate get cpg' do
    cpg_name = 'cpg_1'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/cpg.json')
    cpg_response = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:get_cpg).with(cpg_name).and_return(cpg_response)
    expect(client.get_cpg(cpg_name)).to eq(cpg_response)
  end

  it 'validate create cpg' do
    cpg_name = 'cpg_1'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:create_cpg).and_return(expected_response)
    expect(client.create_cpg(cpg_name)).to eq(expected_response)
  end

  it 'validate modify cpg' do
    cpg_name = 'cpg_1'
    new_cpg_name = 'new_cpg'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:modify_cpg).and_return(expected_response)
    expect(client.modify_cpg(cpg_name, 'newName' => new_cpg_name)).to eq(expected_response)
  end

  it 'validate delete cpg' do
    cpg_name = 'cpg_1'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:delete_cpg).and_return(expected_response)
    expect(client.delete_cpg(cpg_name)).to eq(expected_response)
  end

  it 'validate get cpg available space' do
    cpg_name = 'cpg_1'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    cpg_obj = HPE3PARClient::CPGManager.new(http)
    client.instance_variable_set('@cpg', cpg_obj)
    allow(cpg_obj).to receive(:get_cpg_available_space).and_return(expected_response)
    expect(client.get_cpg_available_space(cpg_name)).to eq(expected_response)
  end

  it 'validate get ports members' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/ports.json')
    all_ports_response = JSON.parse(file)
    all_ports_members = all_ports_response['members']
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    port_obj = HPE3PARClient::PortManager.new(http)
    client.instance_variable_set('@port', port_obj)
    allow(port_obj).to receive(:get_ports).and_return(all_ports_members)
    expect(client.get_ports).to eq(all_ports_members)
  end

  it 'validate get fc ports members' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/fc_ports.json')
    fc_ports_members = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    port_obj = HPE3PARClient::PortManager.new(http)
    client.instance_variable_set('@port', port_obj)
    allow(port_obj).to receive(:get_fc_ports).and_return(fc_ports_members)
    expect(client.get_fc_ports).to eq(fc_ports_members)
  end

  it 'validate get iscsi ports members' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    port_obj = HPE3PARClient::PortManager.new(http)
    client.instance_variable_set('@port', port_obj)
    allow(port_obj).to receive(:get_iscsi_ports).and_return([])
    expect(client.get_iscsi_ports).to eq([])
  end

  it 'validate get ip ports members' do
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    file = File.read('spec/json/ip_ports.json')
    ip_ports_members = JSON.parse(file)
    allow_any_instance_of(HPE3PARClient::Client)
        .to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    port_obj = HPE3PARClient::PortManager.new(http)
    client.instance_variable_set('@port', port_obj)
    allow(port_obj).to receive(:get_ip_ports).and_return(ip_ports_members)
    expect(client.get_ip_ports).to eq(ip_ports_members)
  end

  it 'validate delete clone' do
    physical_copy = 'copy_volume'
    expected_response = 'expected_response'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:delete_volume).and_return(expected_response)
    expect(client.delete_physical_copy(physical_copy))
        .to eq(expected_response)
  end

  it 'validate get_online_physical_copy_status' do
    volume_name = 'my_vol'
    expected_response = 1
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_online_physical_copy_status).and_return(expected_response)
    expect(client.get_online_physical_copy_status(volume_name)).to eq(expected_response)
  end

  it 'validate stop physical copy' do
    volume_name = 'my_vol'
    expected_response = nil
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:stop_offline_physical_copy).and_return(expected_response)
    expect(client.stop_offline_physical_copy(volume_name)).to eq(expected_response)
  end

  it 'validate resync physical copy' do
    volume_name = 'my_vol'
    expected_response = nil
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:resync_physical_copy).and_return(expected_response)
    expect(client.resync_physical_copy(volume_name)).to eq(expected_response)
  end

  it 'validate WSAPI version check with unsupported version' do
    @api_unsupported_hash = {'major' => 1, 'minor' => 4, 'revision' => 0, 'build' => 30_102_612}
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_unsupported_hash }
    expect { HPE3PARClient::Client.new(@url) }.to raise_error(HPE3PARClient::UnsupportedVersion)
  end

  it 'validate WSAPI version check with supported version' do
    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    expect(client).to be
  end

  it 'validate get non-existent volume' do
    volume_name = 'vol_doesnt_exist'
    http = HPE3PARClient::HTTPJSONRestClient.new(@url, false, false, false, nil)
    json_response = '{"code": 404, "parsed_reponse":{"code":23,"desc":"volume does not exist"}}'
    response = JSON.parse(json_response)

    allow_any_instance_of(HPE3PARClient::Client).to receive(:get_ws_api_version) { @api_hash }
    client = HPE3PARClient::Client.new(@url)
    vol_obj = HPE3PARClient::VolumeManager.new(http, nil, app_type)
    client.instance_variable_set('@volume', vol_obj)
    allow(vol_obj).to receive(:get_volume).with(volume_name).and_raise(HPE3PARClient::HTTPNotFound)
    expect{ client.get_volume(volume_name) }.to raise_error(HPE3PARClient::HTTPNotFound, 'Not found')
  end

end
