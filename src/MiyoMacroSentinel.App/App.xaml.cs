using System.Windows;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.App;

public partial class App : System.Windows.Application
{
    private readonly SafeLogger _logger = new();

    protected override void OnStartup(System.Windows.StartupEventArgs e)
    {
        DispatcherUnhandledException += (_, args) =>
        {
            _logger.Error(args.Exception, "Unhandled UI exception");
            System.Windows.MessageBox.Show("MiyoMacroSentinel handled an unexpected error. Details were written to logs/error.log.", "MiyoMacroSentinel", MessageBoxButton.OK, MessageBoxImage.Warning);
            args.Handled = true;
        };

        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                _logger.Error(ex, "Unhandled app-domain exception");
            }
        };

        base.OnStartup(e);
    }
}
