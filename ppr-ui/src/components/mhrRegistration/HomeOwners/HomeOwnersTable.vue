<template>
  <v-card id="home-owner-table-card" flat rounded :class="{ 'border-error-left': showTableError}">
    <BaseDialog
      :setOptions="mhrDeceasedOwnerChanges"
      :setDisplay="showOwnerChangesDialog"
      @proceed="handleOwnerChangesDialogResp($event)"
    />

    <v-data-table
      id="mh-home-owners-table"
      class="home-owners-table"
      :class="{ 'review-mode': isReadonlyTable }"
      :headers="homeOwnersTableHeaders"
      hide-default-footer
      :items="homeOwners"
      item-key="groupId"
      :group-by="showGroups ? 'groupId' : null"
      disable-sort
      disable-pagination
    >
      <template
        v-slot:header
        v-if="isMhrTransfer && !hasActualOwners(homeOwners) && homeOwners.length > 0 && hasRemovedAllHomeOwnerGroups()"
      >
        <tr class="fs-14 text-center no-owners-head-row" data-test-id="no-data-msg">
          <td class="pa-6" :colspan="homeOwnersTableHeaders.length">
            No owners added yet.
          </td>
        </tr>
      </template>

      <template v-slot:group.header="{ group, items }" class="group-header-slot">
        <td
          v-if="!(disableGroupHeader(group) && (hideRemovedOwners || isReadonlyTable))"
          :colspan="4"
          class="py-1"
          :class="{'spacer-header': disableGroupHeader(group),
            'border-error-left': showInvalidDeceasedOwnerGroupError(group)
          }"
        >
          <TableGroupHeader
            :groupId="group"
            :groupNumber="getGroupNumberById(group)"
            :owners="hasActualOwners(items) ? items : []"
            :showEditActions="showEditActions && enableTransferOwnerGroupActions()"
            :disableGroupHeader="disableGroupHeader(group)"
            :isMhrTransfer="isMhrTransfer"
          />
        </td>
      </template>

      <template v-slot:item="row" v-if="homeOwners.length">

        <!-- Transfer scenario: Display error for groups that 'removed' all owners but they still exist in the table -->
        <tr v-if="isGroupWithNoOwners(row.item, row.index)">
          <td :colspan="4" class="py-1">
            <div
              class="error-text my-6 text-center"
              :data-test-id="`no-owners-msg-group-${homeOwners.indexOf(row.item)}`"
            >
              Group must contain at least one owner.
            </div>
          </td>
        </tr>

        <tr v-if="isCurrentlyEditing(homeOwners.indexOf(row.item))">
          <td class="pa-0" :colspan="homeOwnersTableHeaders.length">
            <v-expand-transition>
              <AddEditHomeOwner
                :editHomeOwner="row.item"
                :isHomeOwnerPerson="!row.item.organizationName"
                :isMhrTransfer="isMhrTransfer"
                :showTableError="validateTransfer && (isAddingMode || isEditingMode)"
                @cancel="currentlyEditingHomeOwnerId = -1"
                @remove="removeOwnerHandler(row.item)"
              />
            </v-expand-transition>
          </td>
        </tr>

        <tr
          v-else-if="row.item.ownerId"
          :key="`owner-row-key-${homeOwners.indexOf(row.item)}`"
          class="owner-info"
          :data-test-id="`owner-info-${row.item.ownerId}`"
        >
          <td
            class="owner-name"
            :class="{'no-bottom-border' : isRemovedHomeOwner(row.item) && showDeathCertificate(),
              'border-error-left': showInvalidDeceasedOwnerGroupError(row.item.groupId) }"
          >
            <div :class="{'removed-owner': isRemovedHomeOwner(row.item)}">
              <div v-if="row.item.individualName" class="owner-icon-name">
                <v-icon
                  class="mr-2"
                  :class="{'person-executor-icon': row.item.partyType === HomeOwnerPartyTypes.EXECUTOR}"
                >
                  {{ row.item.partyType === HomeOwnerPartyTypes.EXECUTOR ?
                    '$vuetify.icons.values.ExecutorPersonIcon' : 'mdi-account' }}
                </v-icon>
                <div class="font-weight-bold">
                  {{ row.item.individualName.first }}
                  {{ row.item.individualName.middle }}
                  {{ row.item.individualName.last }}
                </div>
              </div>
              <div v-else class="owner-icon-name">
                <v-icon
                  class="mr-2"
                  :class="{'business-executor-icon': row.item.partyType === HomeOwnerPartyTypes.EXECUTOR}"
                >
                  {{ row.item.partyType === HomeOwnerPartyTypes.EXECUTOR ?
                    '$vuetify.icons.values.ExecutorBusinessIcon' : 'mdi-domain' }}
                </v-icon>
                <div class="font-weight-bold">
                  {{ row.item.organizationName }}
                </div>
              </div>
              <div v-if="row.item.suffix" class="font-light">
                {{ row.item.suffix }}
              </div>
            </div>

            <!-- Hide Chips for Review Mode -->
            <template v-if="!isReadonlyTable || showChips">
              <v-chip
                v-if="isMhrTransfer && isAddedHomeOwner(row.item)"
                class="badge-added ml-8 mt-2"
                color="primary"
                label x-small
                text-color="white"
                data-test-id="owner-added-badge"
              >
                <b>ADDED</b>
              </v-chip>
              <v-chip
                v-if="isMhrTransfer && isChangedOwner(row.item)"
                class="badge-changed ml-8 mt-2"
                color="primary"
                label x-small
                text-color="white"
                data-test-id="owner-changed-badge"
              >
                <b>CHANGED</b>
              </v-chip>
              <v-chip
                v-if="isMhrTransfer && isRemovedHomeOwner(row.item)"
                class="badge-delete ml-8 mt-2"
                label x-small
                color="#grey lighten-2"
                text-color="$gray9"
                data-test-id="owner-removed-badge"
              >
                <b>{{showDeathCertificate() ? 'DECEASED' : 'DELETED'}}</b>
              </v-chip>
            </template>
          </td>
          <td :class="{'no-bottom-border' : isRemovedHomeOwner(row.item) && showDeathCertificate()}">
            <base-address
              :schema="addressSchema"
              :value="row.item.address"
              :class="{'removed-owner': isRemovedHomeOwner(row.item)}"
            />
          </td>
          <td :class="{'no-bottom-border' : isRemovedHomeOwner(row.item) && showDeathCertificate()}">
            <div :class="{'removed-owner': isRemovedHomeOwner(row.item)}">
              {{ toDisplayPhone(row.item.phoneNumber) }}
              <span v-if="row.item.phoneExtension"> Ext {{ row.item.phoneExtension }} </span>
            </div>
          </td>
          <td v-if="showEditActions" class="row-actions text-right"
            :class="{'no-bottom-border' : isRemovedHomeOwner(row.item) && showDeathCertificate()}">
            <!-- New Owner Actions -->
            <div
              v-if="(!isMhrTransfer || isAddedHomeOwner(row.item)) && enableHomeOwnerChanges()"
              class="mr-n4"
            >
              <v-btn
                text
                color="primary"
                class="mr-n4"
                :ripple="false"
                :disabled="isAddingMode || isEditingMode || isGlobalEditingMode"
                @click="openForEditing(homeOwners.indexOf(row.item))"
                data-test-id="table-edit-btn"
              >
                <v-icon small>mdi-pencil</v-icon>
                <span>Edit</span>
                <v-divider class="ma-0 pl-3" vertical />
              </v-btn>
              <!-- Actions drop down menu -->
              <v-menu offset-y left nudge-bottom="0">
                <template v-slot:activator="{ on }">
                  <v-btn text v-on="on"
                         color="primary" class="px-0"
                         :disabled="isAddingMode || isGlobalEditingMode"
                  >
                    <v-icon>mdi-menu-down</v-icon>
                  </v-btn>
                </template>

                <!-- More actions drop down list -->
                <v-list class="actions-dropdown actions__more-actions">
                  <v-list-item class="my-n2">
                    <v-list-item-subtitle class="pa-0" @click="remove(row.item)">
                      <v-icon small style="margin-bottom: 3px;">mdi-delete</v-icon>
                      <span class="ml-1 remove-btn-text">Remove</span>
                    </v-list-item-subtitle>
                  </v-list-item>
                </v-list>
              </v-menu>
            </div>

            <!-- Existing Owner Actions -->
            <template v-else-if="enableTransferOwnerActions(row.item)">
              <v-btn
                v-if="!isRemovedHomeOwner(row.item) && !isChangedOwner(row.item)"
                text color="primary" class="mr-n4"
                :ripple="false"
                :disabled="isAddingMode || isEditingMode || isGlobalEditingMode || isDisabledForSJTChanges(row.item)"
                @click="markForRemoval(row.item)"
                data-test-id="table-delete-btn"
              >
                <v-icon small>mdi-delete</v-icon>
                <span>Delete</span>
                <v-divider v-if="enableTransferOwnerMenuActions(row.item)" class="ma-0 pl-3" vertical />
              </v-btn>

              <v-btn
                v-if="isRemovedHomeOwner(row.item) || isChangedOwner(row.item)"
                text color="primary" class="mr-n4"
                :ripple="false"
                :disabled="isAddingMode || isEditingMode || isGlobalEditingMode || isDisabledForSJTChanges(row.item)"
                @click="undo(row.item)"
                data-test-id="table-undo-btn"
              >
                <v-icon small>mdi-undo</v-icon>
                <span>Undo</span>
                <v-divider
                  v-if="enableTransferOwnerMenuActions(row.item) && !isRemovedHomeOwner(row.item)"
                  class="ma-0 pl-3" vertical
                />
              </v-btn>

              <!-- Menu actions drop down menu -->
              <template v-if="enableTransferOwnerMenuActions(row.item) && !isRemovedHomeOwner(row.item)">
                <v-menu offset-y left nudge-bottom="0">
                  <template v-slot:activator="{ on }">
                    <v-btn
                      text v-on="on"
                      color="primary"
                      class="px-0 mr-n3"
                      :disabled="isAddingMode || isGlobalEditingMode || isDisabledForSJTChanges(row.item)"
                    >
                      <v-icon>mdi-menu-down</v-icon>
                    </v-btn>
                  </template>

                  <!-- More actions drop down list -->
                  <v-list class="actions-dropdown actions__more-actions">
                    <!-- Menu Edit Option -->
                    <v-list-item class="my-n2">
                      <v-list-item-subtitle class="pa-0" @click="openForEditing(homeOwners.indexOf(row.item))">
                        <v-icon small class="mb-1">mdi-pencil</v-icon>
                        <span class="ml-1 remove-btn-text">Change Details</span>
                      </v-list-item-subtitle>
                    </v-list-item>

                    <!-- Menu Delete Option -->
                    <v-list-item class="my-n2" v-if="isChangedOwner(row.item)">
                      <v-list-item-subtitle class="pa-0" @click="removeChangeOwnerHandler(row.item)">
                        <v-icon small class="mb-1">mdi-delete</v-icon>
                        <span class="ml-1 remove-btn-text">Delete</span>
                      </v-list-item-subtitle>
                    </v-list-item>
                  </v-list>
                </v-menu>
              </template>
            </template>
          </td>
        </tr>
        <!-- For MHR scenarios where users can entirely remove added owners -->
        <tr v-else-if="!hideRemovedOwners && !showGroups">
          <td :colspan="4" class="py-1">
            <div class="my-6 text-center" data-test-id="no-owners-mgs">
              No owners added yet.
            </div>
          </td>
        </tr>
        <tr
          v-if="isRemovedHomeOwner(row.item) && showDeathCertificate() && !isReadonlyTable"
          class="death-certificate-row"
        >
          <td
            :colspan="homeOwnersTableHeaders.length"
            class="py-0"
            :class="{ 'border-error-left': showInvalidDeceasedOwnerGroupError(row.item.groupId) }"
          >
            <v-expand-transition>
              <DeathCertificate
                :deceasedOwner="row.item"
                :validate="validateTransfer"
                @isValid="isValidDeathCertificate = $event"
              />
            </v-expand-transition>
          </td>
        </tr>
        <tr v-else-if="isRemovedHomeOwner(row.item) && showDeathCertificate() && isReadonlyTable">
          <td :colspan="homeOwnersTableHeaders.length" class="deceased-review-info">
            <v-row no-gutters class="ml-8 my-n3">
              <v-col cols="12">
                <p class="generic-label fs-14">Death Certificate Registration Number:
                  <span class="font-light mx-1">{{row.item.deathCertificateNumber}}</span>
                </p>
              </v-col>
              <v-col cols="12">
                <p class="generic-label fs-14 mt-n4">Date of Death:
                  <span class="font-light mx-1">{{yyyyMmDdToPacificDate(row.item.deathDateTime, true)}}</span>
                </p>
              </v-col>
            </v-row>
          </td>
        </tr>
      </template>

      <template v-slot:no-data>
        <div class="pa-4 text-center" data-test-id="no-data-msg">No owners added yet.</div>
      </template>
    </v-data-table>
  </v-card>
</template>

<script lang="ts">
import { computed, defineComponent, reactive, toRefs, watch } from '@vue/composition-api'
import { homeOwnersTableHeaders, homeOwnersTableHeadersReview } from '@/resources/tableHeaders'
import { useHomeOwners, useMhrInfoValidation, useMhrValidations, useTransferOwners } from '@/composables'
import { BaseAddress } from '@/composables/address'
import { PartyAddressSchema } from '@/schemas'
import { toDisplayPhone } from '@/utils'
import { AddEditHomeOwner } from '@/components/mhrRegistration/HomeOwners'
import { DeathCertificate } from '@/components/mhrTransfers'
import { BaseDialog } from '@/components/dialogs'
import TableGroupHeader from '@/components/mhrRegistration/HomeOwners/TableGroupHeader.vue'
import { mhrDeceasedOwnerChanges } from '@/resources/dialogOptions'
import { yyyyMmDdToPacificDate } from '@/utils/date-helper'
/* eslint-disable no-unused-vars */
import { MhrRegistrationHomeOwnerIF } from '@/interfaces'
import { ActionTypes, ApiTransferTypes, HomeTenancyTypes, HomeOwnerPartyTypes } from '@/enums'
/* eslint-enable no-unused-vars */
import { useActions, useGetters } from 'vuex-composition-helpers'

export default defineComponent({
  name: 'HomeOwnersTable',
  emits: ['isValidTransferOwners'],
  props: {
    homeOwners: { default: () => [] },
    isAdding: { default: false },
    isReadonlyTable: { type: Boolean, default: false },
    isMhrTransfer: { type: Boolean, default: false },
    hideRemovedOwners: { type: Boolean, default: false },
    showChips: { type: Boolean, default: false },
    validateTransfer: { type: Boolean, default: false }
  },
  components: {
    BaseAddress,
    BaseDialog,
    AddEditHomeOwner,
    TableGroupHeader,
    DeathCertificate
  },
  setup (props, context) {
    const addressSchema = PartyAddressSchema

    const {
      showGroups,
      removeOwner,
      deleteGroup,
      isGlobalEditingMode,
      setGlobalEditingMode,
      hasEmptyGroup,
      hasMinimumGroups,
      editHomeOwner,
      getGroupById,
      undoGroupRemoval,
      getHomeTenancyType,
      getGroupNumberById,
      hasRemovedAllHomeOwners,
      hasRemovedAllHomeOwnerGroups,
      hasUndefinedGroupInterest,
      getTotalOwnershipAllocationStatus,
      getTransferOrRegistrationHomeOwners,
      getTransferOrRegistrationHomeOwnerGroups
    } = useHomeOwners(props.isMhrTransfer)

    const {
      enableHomeOwnerChanges,
      enableTransferOwnerActions,
      enableTransferOwnerGroupActions,
      enableTransferOwnerMenuActions,
      showDeathCertificate,
      isDisabledForSJTChanges,
      isCurrentOwner,
      getCurrentOwnerStateById,
      isTransferDueToDeath,
      groupHasRemovedAllCurrentOwners,
      moveCurrentOwnersToPreviousOwners
    } = useTransferOwners(!props.isMhrTransfer)

    const { setUnsavedChanges } = useActions<any>(['setUnsavedChanges'])

    const { getMhrRegistrationValidationModel, getMhrInfoValidation, hasUnsavedChanges } =
      useGetters<any>(['getMhrRegistrationValidationModel', 'getMhrInfoValidation', 'hasUnsavedChanges'])

    const { getValidation, MhrSectVal, MhrCompVal } = useMhrValidations(toRefs(getMhrRegistrationValidationModel.value))
    const { isValidDeceasedOwnerGroup } = useMhrInfoValidation(getMhrInfoValidation.value)

    const localState = reactive({
      currentlyEditingHomeOwnerId: -1,
      reviewed: false,
      showOwnerChangesDialog: false,
      ownerToDecease: null as MhrRegistrationHomeOwnerIF,
      isEditingMode: computed((): boolean => localState.currentlyEditingHomeOwnerId >= 0),
      isAddingMode: computed((): boolean => props.isAdding),
      isValidDeathCertificate: false,
      showTableError: computed((): boolean => {
        return (props.validateTransfer || localState.reviewedOwners) &&
            (
              !hasMinimumGroups() ||
              hasEmptyGroup.value ||
              (props.isMhrTransfer && !hasUnsavedChanges.value) ||
              !localState.isValidAllocation ||
              localState.hasGroupsWithNoOwners ||
              (!localState.isUngroupedTenancy && hasUndefinedGroupInterest(getTransferOrRegistrationHomeOwnerGroups()))
            )
      }),
      reviewedOwners: computed((): boolean =>
        getValidation(MhrSectVal.REVIEW_CONFIRM_VALID, MhrCompVal.VALIDATE_STEPS)),
      showEditActions: computed((): boolean => !props.isReadonlyTable),
      homeOwnersTableHeaders: props.isReadonlyTable ? homeOwnersTableHeadersReview : homeOwnersTableHeaders,
      addedOwnerCount: computed((): number => {
        return getTransferOrRegistrationHomeOwners().filter(owner => owner.action === ActionTypes.ADDED).length
      }),
      addedGroupCount: computed((): number => {
        return getTransferOrRegistrationHomeOwnerGroups().filter(group => group.action === ActionTypes.ADDED).length
      }),
      hasGroupsWithNoOwners: computed((): boolean => {
        const groups = getTransferOrRegistrationHomeOwnerGroups().filter(group => group.action !== ActionTypes.REMOVED)
        return groups.some(group => group.owners.filter(owner => owner.action !== ActionTypes.REMOVED).length === 0)
      }),
      isValidAllocation: computed((): boolean => {
        return localState.isUngroupedTenancy || !getTotalOwnershipAllocationStatus().hasTotalAllocationError
      }),
      isUngroupedTenancy: computed((): boolean => {
        return [HomeTenancyTypes.SOLE, HomeTenancyTypes.JOINT].includes(getHomeTenancyType())
      })
    })

    const showInvalidDeceasedOwnerGroupError = (groupId): boolean => {
      return props.validateTransfer && !isValidDeceasedOwnerGroup(groupId) && !localState.showTableError
    }

    const remove = (item): void => {
      localState.currentlyEditingHomeOwnerId = -1
      setUnsavedChanges(true)
      removeOwner(item)
    }

    const markForRemoval = (item: MhrRegistrationHomeOwnerIF): void => {
      localState.currentlyEditingHomeOwnerId = -1
      editHomeOwner(
        { ...item, action: ActionTypes.REMOVED },
        item.groupId
      )

      // When base ownership is SO/JT and all current owners have been removed: Move them to a previous owners group.
      if (groupHasRemovedAllCurrentOwners(item.groupId) && showGroups.value) {
        moveCurrentOwnersToPreviousOwners(item.groupId)
      }
    }

    const undo = async (item: MhrRegistrationHomeOwnerIF): Promise<void> => {
      await editHomeOwner(
        { ...getCurrentOwnerStateById(item.ownerId), action: null },
        item.groupId
      )
      await undoGroupRemoval(item.groupId)
    }

    const openForEditing = (index: number) => {
      localState.currentlyEditingHomeOwnerId = index
    }

    const isCurrentlyEditing = (index: number): boolean => {
      return index === localState.currentlyEditingHomeOwnerId
    }

    // To render Group table header the owners array must not be empty
    // check for at least one owner with an id
    // This util function will help to show Owners: 0 in the table header
    const hasActualOwners = (owners: MhrRegistrationHomeOwnerIF[]): boolean => {
      const activeOwners = owners.filter(owner => owner.action !== ActionTypes.REMOVED)
      return activeOwners.length > 0 && activeOwners.some(owner => owner.ownerId !== undefined)
    }

    const isAddedHomeOwner = (item: MhrRegistrationHomeOwnerIF): boolean => {
      return item.action === ActionTypes.ADDED
    }

    const isAddedHomeOwnerGroup = (groupId: number): boolean => {
      return getGroupById(groupId)?.action === ActionTypes.ADDED
    }

    const isChangedOwner = (item: MhrRegistrationHomeOwnerIF): boolean => {
      return item.action === ActionTypes.CHANGED
    }

    const isRemovedHomeOwner = (item: MhrRegistrationHomeOwnerIF): boolean => {
      return item.action === ActionTypes.REMOVED
    }

    const hasNoGroupInterest = (groupId: number): boolean => {
      const group = getGroupById(groupId)
      return !group.interestNumerator && !group.interestDenominator
    }

    const disableGroupHeader = (groupId: number): boolean => {
      const currentOwners = props.homeOwners.filter(owner => owner.action !== ActionTypes.ADDED)

      return hasRemovedAllHomeOwners(currentOwners) &&
        isAddedHomeOwnerGroup(groupId) &&
        hasNoGroupInterest(groupId) &&
        localState.addedGroupCount <= 1
    }

    const isGroupWithNoOwners = (owner: MhrRegistrationHomeOwnerIF, index: number): boolean => {
      const group = getGroupById(owner.groupId)
      const hasNoOwners = group.action !== ActionTypes.REMOVED && group.interestNumerator &&
        group.interestDenominator && group.owners.filter(owner => owner.action !== ActionTypes.REMOVED).length === 0

      return hasNoOwners && index === 0
    }

    const removeOwnerHandler = (owner: MhrRegistrationHomeOwnerIF): void => {
      isCurrentOwner(owner)
        ? isChangedOwner(owner) ? removeChangeOwnerHandler(owner) : markForRemoval(owner)
        : remove(owner)
    }

    const removeChangeOwnerHandler = (owner: MhrRegistrationHomeOwnerIF): void => {
      localState.ownerToDecease = { ...getCurrentOwnerStateById(owner.ownerId), groupId: owner.groupId }
      localState.showOwnerChangesDialog = true
    }

    const handleOwnerChangesDialogResp = async (val: boolean): Promise<void> => {
      if (!val) {
        localState.showOwnerChangesDialog = false
        return
      }

      await markForRemoval(localState.ownerToDecease)
      localState.showOwnerChangesDialog = false
      localState.ownerToDecease = null
    }

    watch(() => localState.currentlyEditingHomeOwnerId, () => {
      setGlobalEditingMode(localState.isEditingMode)
    })

    // When a change is made to homeOwners, check if any actions have changed, if so set flag
    watch(() => props.homeOwners, (val) => {
      setUnsavedChanges(val.some(owner => !!owner.action || !owner.ownerId))
      context.emit('isValidTransferOwners',
        hasMinimumGroups() &&
        localState.isValidAllocation &&
        !localState.hasGroupsWithNoOwners &&
        (!isTransferDueToDeath.value || localState.isValidDeathCertificate)
      )
    }, { deep: true })

    watch(
      () => enableTransferOwnerGroupActions(),
      (val: boolean) => {
        localState.currentlyEditingHomeOwnerId = -1
      }
    )

    return {
      ActionTypes,
      addressSchema,
      toDisplayPhone,
      openForEditing,
      isCurrentlyEditing,
      showGroups,
      hasEmptyGroup,
      hasActualOwners,
      remove,
      deleteGroup,
      isGlobalEditingMode,
      hasMinimumGroups,
      isAddedHomeOwner,
      isChangedOwner,
      isRemovedHomeOwner,
      markForRemoval,
      undo,
      hasRemovedAllHomeOwners,
      hasRemovedAllHomeOwnerGroups,
      isAddedHomeOwnerGroup,
      disableGroupHeader,
      isGroupWithNoOwners,
      getGroupNumberById,
      getTransferOrRegistrationHomeOwners,
      getTransferOrRegistrationHomeOwnerGroups,
      enableHomeOwnerChanges,
      enableTransferOwnerActions,
      enableTransferOwnerGroupActions,
      enableTransferOwnerMenuActions,
      showDeathCertificate,
      isDisabledForSJTChanges,
      isCurrentOwner,
      mhrDeceasedOwnerChanges,
      removeOwnerHandler,
      removeChangeOwnerHandler,
      handleOwnerChangesDialogResp,
      yyyyMmDdToPacificDate,
      showInvalidDeceasedOwnerGroupError,
      HomeOwnerPartyTypes,
      ...toRefs(localState)
    }
  }
})
</script>

<style lang="scss" scoped>
@import '@/assets/styles/theme.scss';

.home-owners-table ::v-deep {
  .person-executor-icon {
    margin-top: -3px !important;
    height: 22px !important;
    width: 22px !important;
  }
  .business-executor-icon {
    margin-top: -8px !important;
    margin-left: -4px !important;
    height: 29px !important;
    width: 28px !important;
  }
  .spacer-header {
    border-color: $gray1 !important;
    background-color: $gray1 !important;
  }

  .no-bottom-border {
    border-bottom: none !important;
  }

  .death-certificate-row {
    border-bottom: thin solid rgba(0, 0, 0, 0.12) !important;
  }

  tr.v-row-group__header,
  tbody tr.v-row-group__header:hover {
    background-color: $app-lt-blue;
  }

  .no-owners-head-row {
    color: $gray7;
  }

  .owner-name,
  .owner-name i {
    color: $gray9 !important;
  }

  .removed-owner {
    opacity: .4;
  }

  table {
    tbody > tr > td {
      padding: 20px 12px;
    }
    th:first-child,
    td:first-child {
      padding-left: 30px;
    }
    td:last-child {
      padding-right: 30px;
      padding-top: 8px;
    }
    tbody > tr.v-row-group__header,
    tbody > tr.v-row-group__header:hover {
      background: $app-lt-blue !important;
    }

    .no-owners-error {
      text-align: center;
      color: $error;
    }
  }

  .owner-icon-name {
    display: flex;
    align-items: flex-start;
    div {
      word-break: break-word;
    }
    i {
      margin-top: -3px;
    }
  }
  .owner-info {
    td {
      white-space: normal;
      vertical-align: top;
    }
  }

  .v-data-table-header th {
    padding: 0 12px;
  }

  .font-light, {
    color: $gray7;
    font-size: 14px;
    line-height: 22px;
    margin-left: 32px;
    font-weight: normal;
  }
  .theme--light.v-btn.v-btn--disabled {
    color: #1669bb !important;
    opacity: 0.4 !important;
  }
}

.v-menu__content {
  cursor: pointer;
}
.review-mode ::v-deep {
  table {
    th:first-child,
    td:first-child {
      padding-left: 0 !important;
    }
  }
  tbody > tr.v-row-group__header {
    margin-left: 20px !important;
    padding-left: 20px !important;
  }
}
</style>
