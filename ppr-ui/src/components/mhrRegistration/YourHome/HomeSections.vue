<template>
  <div id="mhr-home-sections-shim">
    <v-row v-if="!isReviewMode" no-gutters>
      <v-btn
        outlined
        class="mt-1 add-home-section-btn"
        color="primary"
        :ripple="false"
        :disabled="showAddEditHomeSections || isEditingHomeSection"
        @click="openAddNewHomeSectionForm()"
      >
        <v-icon class="pr-1">mdi-home-plus</v-icon> Add a Section
      </v-btn>
      <span v-if="displayHomeSectionsError && isMaxHomeSections" class="pl-7 pt-4 error-text">
        Your registration cannot contain more than four sections
      </span>
    </v-row>

    <v-row no-gutters class="mt-6">
      <p v-if="!isReviewMode" id="section-count">Number of Sections: {{getMhrHomeSections.length}}</p>
      <span v-if="validate && !hasMinimumHomeSections" class="pl-4 error-text">
          Your registration must contain at least one section
        </span>
    </v-row>

    <!-- Add New Home Section Form -->
    <v-expand-transition>
      <AddEditHomeSections
        v-if="showAddEditHomeSections"
        :isNewHomeSection="isNewHomeSection"
        @close="showAddEditHomeSections = false"
        @submit="addHomeSection($event)"
      />
    </v-expand-transition>

    <!-- Home Sections Table -->
    <HomeSectionsTable
      :class="{ 'border-error-left': validate }"
      :isAdding="showAddEditHomeSections"
      :homeSections="getMhrHomeSections"
      :isReviewMode="isReviewMode"
      @isEditing="isEditingHomeSection = $event"
      @edit="editHomeSection($event)"
      @remove="removeHomeSection($event)"
    />
  </div>
</template>

<script lang="ts">
/* eslint-disable no-unused-vars */
import { computed, defineComponent, reactive, toRefs, watch } from '@vue/composition-api'
import { useActions, useGetters } from 'vuex-composition-helpers'
import { HomeSectionIF } from '@/interfaces'
import AddEditHomeSections from '@/components/mhrRegistration/YourHome/AddEditHomeSections.vue'
import HomeSectionsTable from '@/components/tables/mhr/HomeSectionsTable.vue'
import { setMhrHomeDescription } from '@/store/actions'
import { useMhrValidations } from '@/composables'
/* eslint-enable no-unused-vars */

export default defineComponent({
  name: 'HomeSections',
  components: {
    AddEditHomeSections,
    HomeSectionsTable
  },
  props: {
    isReviewMode: {
      type: Boolean,
      default: false
    },
    validate: {
      type: Boolean,
      default: false
    }
  },
  setup () {
    const {
      setMhrHomeDescription
    } = useActions<any>([
      'setMhrHomeDescription'
    ])

    const {
      getMhrHomeSections,
      getMhrRegistrationValidationModel
    } = useGetters<any>([
      'getMhrHomeSections',
      'getMhrRegistrationValidationModel'
    ])

    const {
      MhrCompVal,
      MhrSectVal,
      setValidation
    } = useMhrValidations(toRefs(getMhrRegistrationValidationModel.value))

    const localState = reactive({
      isEditingHomeSection: false,
      isNewHomeSection: true,
      displayHomeSectionsError: false,
      showAddEditHomeSections: false,
      isMaxHomeSections: computed((): boolean => {
        return getMhrHomeSections.value.length === 4
      }),
      hasMinimumHomeSections: computed((): boolean => {
        return getMhrHomeSections.value.length >= 1
      })
    })

    const openAddNewHomeSectionForm = (): void => {
      if (!localState.isMaxHomeSections) {
        localState.showAddEditHomeSections = true
        localState.displayHomeSectionsError = false
      } else localState.displayHomeSectionsError = true
    }

    const addHomeSection = (homeSection: HomeSectionIF): void => {
      const homeSections = [...getMhrHomeSections.value]
      // Add new home section to array
      homeSections.push(homeSection)
      setMhrHomeDescription({ key: 'sections', value: homeSections })
    }

    const editHomeSection = (homeSection: HomeSectionIF): void => {
      const homeSections = [...getMhrHomeSections.value]
      // Create edited homeSection without id
      const { id, ...editedSection } = homeSection
      // Apply edited section to temp array
      homeSections[homeSection.id] = editedSection

      setMhrHomeDescription({ key: 'sections', value: homeSections })
    }

    const removeHomeSection = (homeSection: HomeSectionIF): void => {
      const homeSections = [...getMhrHomeSections.value]
      // Remove home section from array
      homeSections.splice(homeSections.indexOf(homeSection), 1)
      setMhrHomeDescription({ key: 'sections', value: homeSections })
    }

    watch(() => localState.hasMinimumHomeSections, (val: boolean) => {
      setValidation(MhrSectVal.YOUR_HOME_VALID, MhrCompVal.HOME_SECTION_VALID, val)
    })

    watch(() => localState.showAddEditHomeSections, (val: boolean) => {
      setValidation(MhrSectVal.YOUR_HOME_VALID, MhrCompVal.HOME_SECTION_VALID,
        !localState.showAddEditHomeSections && localState.hasMinimumHomeSections)
    })

    watch(() => localState.isEditingHomeSection, (val: boolean) => {
      setValidation(MhrSectVal.YOUR_HOME_VALID, MhrCompVal.HOME_SECTION_VALID,
        !localState.isEditingHomeSection && localState.hasMinimumHomeSections)
    })

    return {
      addHomeSection,
      editHomeSection,
      removeHomeSection,
      openAddNewHomeSectionForm,
      getMhrHomeSections,
      ...toRefs(localState)
    }
  }
})
/* eslint-enable no-unused-vars */
</script>

<style lang="scss" scoped>
@import '@/assets/styles/theme.scss';
</style>
