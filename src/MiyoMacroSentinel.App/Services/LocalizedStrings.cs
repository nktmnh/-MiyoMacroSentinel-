using System.ComponentModel;
using System.Globalization;
using System.Resources;

namespace MiyoMacroSentinel.App.Services;

public sealed class LocalizedStrings : INotifyPropertyChanged
{
    private readonly ResourceManager _resources = new("MiyoMacroSentinel.App.Resources.Resources", typeof(LocalizedStrings).Assembly);
    private CultureInfo _culture = CultureInfo.GetCultureInfo("vi");

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Language => _culture.TwoLetterISOLanguageName;

    public string this[string key]
    {
        get
        {
            try
            {
                return _resources.GetString(key, _culture) ?? key;
            }
            catch
            {
                return key;
            }
        }
    }

    public void SetLanguage(string language)
    {
        _culture = CultureInfo.GetCultureInfo(language.Equals("en", StringComparison.OrdinalIgnoreCase) ? "en" : "vi");
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Language)));
    }
}
