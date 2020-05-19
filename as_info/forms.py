from django import forms


class SearchForm(forms.Form):
    wiki_url = forms.CharField(
        label="Path to the wiki",
        required=False,
    )
    ip = forms.CharField(
        label="IP Address or Range",
        required=False,
    )
    asn = forms.CharField(
        label="AS Number",
        required=False,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
