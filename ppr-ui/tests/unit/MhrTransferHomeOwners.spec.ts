import Vue from 'vue'
import Vuetify from 'vuetify'
import { getVuexStore } from '@/store'
import { mount, createLocalVue, Wrapper } from '@vue/test-utils'

import { HomeOwners } from '@/views'
import {
  AddEditHomeOwner,
  HomeOwnersTable,
  HomeOwnerGroups
} from '@/components/mhrRegistration/HomeOwners'
import { SimpleHelpToggle } from '@/components/common'
import {
  mockedPerson,
  mockedOrganization,
  mockedAddedPerson,
  mockedAddedOrganization,
  mockedRemovedPerson, mockedRemovedOrganization
} from './test-data'
import { getTestId } from './utils'
import { MhrRegistrationHomeOwnerGroupIF } from '@/interfaces'
import { ApiTransferTypes, UITransferTypes } from '@/enums'

Vue.use(Vuetify)

const vuetify = new Vuetify({})
const store = getVuexStore()

function createComponent (): Wrapper<any> {
  const localVue = createLocalVue()
  localVue.use(Vuetify)

  document.body.setAttribute('data-app', 'true')
  return mount(HomeOwners, {
    localVue,
    propsData: {
      isMhrTransfer: true
    },
    store,
    vuetify
  })
}

// Error message class selector
const ERROR_MSG = '.error--text .v-messages__message'

describe('Home Owners', () => {
  let wrapper: Wrapper<any>

  beforeEach(async () => {
    wrapper = createComponent()

    await store.dispatch('setMhrTransferType',
      {
        transferType: ApiTransferTypes.SALE_OR_GIFT,
        textLabel: UITransferTypes.SALE_OR_GIFT
      })
  })
  afterEach(() => {
    wrapper.destroy()
  })

  // Helper functions

  const openAddPerson = async () => {
    const homeOwnersSection = wrapper.findComponent(HomeOwners)
    await homeOwnersSection.find(getTestId('add-person-btn'))?.trigger('click')
    await Vue.nextTick()
    expect(homeOwnersSection.findComponent(AddEditHomeOwner).exists()).toBeTruthy()
    expect(homeOwnersSection.findComponent(HomeOwnerGroups).exists()).toBeTruthy()
  }

  const openAddOrganization = async () => {
    const homeOwnersSection = wrapper.findComponent(HomeOwners)
    await homeOwnersSection.find(getTestId('add-org-btn'))?.trigger('click')
    await Vue.nextTick()
    expect(homeOwnersSection.findComponent(AddEditHomeOwner).exists()).toBeTruthy()
    expect(homeOwnersSection.findComponent(HomeOwnerGroups).exists()).toBeTruthy()
  }

  const clickCancelAddOwner = async () => {
    const homeOwnersSection = wrapper.findComponent(HomeOwners)
    const addOwnerSection = homeOwnersSection.findComponent(AddEditHomeOwner)
    expect(addOwnerSection.exists).toBeTruthy()
    const cancelBtn = addOwnerSection.find(getTestId('cancel-btn'))
    expect(cancelBtn.exists()).toBeTruthy()
    await cancelBtn.trigger('click')
    await Vue.nextTick()
    expect(homeOwnersSection.findComponent(AddEditHomeOwner).exists()).toBeFalsy()
  }

  const clickDoneAddOwner = async () => {
    const addOwnerSection = wrapper.findComponent(AddEditHomeOwner)
    const doneBtn = addOwnerSection.find(getTestId('done-btn'))
    expect(doneBtn.exists()).toBeTruthy()

    await doneBtn.trigger('click')
    // should not be any errors
    // expect(addOwnerSection.findAll(ERROR_MSG).length).toBe(0)
    setTimeout(async () => {
      expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy() // Hidden by default
    }, 500)
  }

  // Tests

  it('renders Home Owners and its sub components', () => {
    expect(wrapper.findComponent(HomeOwners).exists()).toBeTruthy()
    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy() // Hidden by default
    expect(wrapper.findComponent(HomeOwnersTable).exists()).toBeTruthy()
    expect(wrapper.findComponent(SimpleHelpToggle).exists()).toBeFalsy() // Verify it doesn't render in Transfers
  })

  it('renders Add Edit Home Owner and its sub components', async () => {
    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBe(false) // Hidden by default
    openAddPerson()
    await Vue.nextTick()
    await Vue.nextTick()
    clickCancelAddOwner()
    await Vue.nextTick()
    await Vue.nextTick()
    openAddOrganization()
    await Vue.nextTick()
    await Vue.nextTick()
    clickCancelAddOwner()
  })

  it('displays CURRENT owners (Persons and Orgs)', async () => {
    const homeOwnerGroup = [{ groupId: 1, owners: [mockedPerson] }] as MhrRegistrationHomeOwnerGroupIF[]

    // add a person
    await store.dispatch('setMhrTransferHomeOwnerGroups', homeOwnerGroup)

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    let ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields

    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedPerson.individualName.first)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.last)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.middle)
    expect(ownersTable.text()).toContain(mockedPerson.suffix)
    expect(ownersTable.text()).toContain(mockedPerson.address.street)
    expect(ownersTable.text()).toContain(mockedPerson.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedPerson.address.city)
    expect(ownersTable.text()).toContain(mockedPerson.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedPerson.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')

    // there should be no 'Added' badge shown for the Current Owners
    const addedBadge = ownersTable.find(getTestId('owner-added-badge'))
    expect(addedBadge.exists()).toBeFalsy()

    // add an organization
    homeOwnerGroup[0].owners.push(mockedOrganization)
    await store.dispatch('setMhrTransferHomeOwnerGroups', homeOwnerGroup)

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields
    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedOrganization.organizationName)
    expect(ownersTable.text()).toContain(mockedOrganization.suffix)
    expect(ownersTable.text()).toContain(mockedOrganization.address.street)
    expect(ownersTable.text()).toContain(mockedOrganization.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedOrganization.address.city)
    expect(ownersTable.text()).toContain(mockedOrganization.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedOrganization.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')
  })

  it('displays badge for ADDED owners (Persons and Orgs)', async () => {
    const homeOwnerGroup = [{ groupId: 1, owners: [mockedAddedPerson, mockedAddedOrganization] }]

    // add a person
    await store.dispatch('setMhrTransferHomeOwnerGroups', homeOwnerGroup)

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    let ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields

    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedPerson.individualName.first)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.last)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.middle)
    expect(ownersTable.text()).toContain(mockedPerson.suffix)
    expect(ownersTable.text()).toContain(mockedPerson.address.street)
    expect(ownersTable.text()).toContain(mockedPerson.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedPerson.address.city)
    expect(ownersTable.text()).toContain(mockedPerson.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedPerson.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields
    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedOrganization.organizationName)
    expect(ownersTable.text()).toContain(mockedOrganization.suffix)
    expect(ownersTable.text()).toContain(mockedOrganization.address.street)
    expect(ownersTable.text()).toContain(mockedOrganization.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedOrganization.address.city)
    expect(ownersTable.text()).toContain(mockedOrganization.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedOrganization.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')

    // there should be 'Added' badges shown for each of the Added Owners
    const addedBadges = ownersTable.findAll(getTestId('owner-added-badge'))
    expect(addedBadges.at(0).exists()).toBe(true)
    expect(addedBadges.at(1).exists()).toBe(true)
  })

  it('displays badge for REMOVED owners (Persons and Orgs)', async () => {
    const homeOwnerGroup = [{ groupId: 1, owners: [mockedRemovedPerson, mockedRemovedOrganization] }]

    // add a person
    await store.dispatch('setMhrTransferHomeOwnerGroups', homeOwnerGroup)

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    let ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields

    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedPerson.individualName.first)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.last)
    expect(ownersTable.text()).toContain(mockedPerson.individualName.middle)
    expect(ownersTable.text()).toContain(mockedPerson.suffix)
    expect(ownersTable.text()).toContain(mockedPerson.address.street)
    expect(ownersTable.text()).toContain(mockedPerson.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedPerson.address.city)
    expect(ownersTable.text()).toContain(mockedPerson.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedPerson.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')

    expect(wrapper.findComponent(AddEditHomeOwner).exists()).toBeFalsy()

    ownersTable = wrapper.findComponent(HomeOwners).findComponent(HomeOwnersTable)

    // renders all fields
    expect(ownersTable.exists()).toBeTruthy()
    expect(ownersTable.text()).toContain(mockedOrganization.organizationName)
    expect(ownersTable.text()).toContain(mockedOrganization.suffix)
    expect(ownersTable.text()).toContain(mockedOrganization.address.street)
    expect(ownersTable.text()).toContain(mockedOrganization.address.streetAdditional)
    expect(ownersTable.text()).toContain(mockedOrganization.address.city)
    expect(ownersTable.text()).toContain(mockedOrganization.address.region)
    expect(ownersTable.text()).toContain('Canada')
    expect(ownersTable.text()).toContain(mockedOrganization.address.postalCode)
    // there should be no grouping shown in the table because we didn't select a group during add
    expect(ownersTable.text()).not.toContain('Group 1')

    // there should be 'Added' badges shown for each of the Added Owners
    const removedBadges = ownersTable.findAll(getTestId('owner-removed-badge'))
    expect(removedBadges.at(0).exists()).toBe(true)
    expect(removedBadges.at(1).exists()).toBe(true)
  })
})
