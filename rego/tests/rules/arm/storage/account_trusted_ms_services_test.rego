# Copyright 2021 Fugue, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

package rules.arm_storage_account_trusted_ms_services

import data.tests.rules.arm.storage.inputs.account_trusted_ms_services_infra_json as infra

test_storage_account_trusted_ms_services {
	allow with input as infra.mock_resources["Microsoft.Storage/storageAccounts/valid"]
	allow with input as infra.mock_resources["Microsoft.Storage/storageAccounts/validmulti"]
	allow with input as infra.mock_resources["Microsoft.Storage/storageAccounts/validmulti2"]
	not allow with input as infra.mock_resources["Microsoft.Storage/storageAccounts/invalid"]
	not allow with input as infra.mock_resources["Microsoft.Storage/storageAccounts/invalidunset"]
}
