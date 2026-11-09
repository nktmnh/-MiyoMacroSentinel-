using System.Windows;
using MiyoMacroSentinel.App.ViewModels;

namespace MiyoMacroSentinel.App;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel();
    }

    private void DropZone_OnDragOver(object sender, System.Windows.DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop) ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void DropZone_OnDrop(object sender, System.Windows.DragEventArgs e)
    {
        if (DataContext is MainViewModel viewModel && e.Data.GetData(System.Windows.DataFormats.FileDrop) is string[] files)
        {
            viewModel.AcceptDroppedFiles(files);
        }
    }
}
