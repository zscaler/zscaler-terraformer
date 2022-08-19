resource "zia_dlp_dictionaries" "terraform_managed_resource" {
  custom_phrase_match_type = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
  dictionary_type          = "EXACT_DATA_MATCH"
  name                     = "SGIO-EDM-Test"
  exact_data_match_details {
    primary_field            = 1
    secondary_field_match_on = "MATCHON_ALL"
  }
}