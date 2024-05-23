from javax.swing import JTable
from javax.swing.table import AbstractTableModel


class Table(JTable):
    def __init__(self, extender):
        # type: (IBurpExtender) -> None
        """Defines internal config"""
        self._extender = extender
        self.setModel(extender)

    def changeSelection(self, row, col, toggle, extend):
        # type: (int, int, int, int) -> None
        """Shows the log entry for the selected row"""
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(
            logEntry._requestResponse.getRequest(), True
        )
        self._extender._responseViewer.setMessage(
            logEntry._requestResponse.getResponse(), False
        )
        self._extender._modifiedRequestViewer.setMessage(
            logEntry._modifiedRequestResponse.getRequest(), True
        )
        self._extender._modifiedResponseViewer.setMessage(
            logEntry._modifiedRequestResponse.getResponse(), False
        )
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        JTable.changeSelection(self, row, col, toggle, extend)


class TableModel(AbstractTableModel):
    def getRowCount(self):
        # type: () -> int
        """Returns the row count of the Param/URL table"""
        try:
            return self._log.size()
        except AttributeError:  # on initialization BurpExtender has no _log
            return 0

    def getColumnCount(self):
        # type: () -> int
        """Returns the magic value `2`: column count for param/URL columns"""
        return 2

    def getColumnName(self, columnIndex):
        # type: (int) -> str
        """Returns the column name based on the selected index"""
        if columnIndex == 0:
            return "Parameter"
        if columnIndex == 1:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        # type: (int, int) -> str
        """Returns the table cell value based on row/column indexes: param or URL"""
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._param
        if columnIndex == 1:
            return logEntry._url
        return ""
