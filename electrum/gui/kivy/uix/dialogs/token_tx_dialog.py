from datetime import datetime
from typing import NamedTuple, Callable

from kivy.app import App
from kivy.factory import Factory
from kivy.properties import ObjectProperty
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.label import Label
from kivy.uix.dropdown import DropDown
from kivy.uix.button import Button

from .question import Question
from electrum.gui.kivy.i18n import _

from electrum.util import InvalidPassword
from electrum.address_synchronizer import TX_HEIGHT_LOCAL
from electrum.wallet import CannotBumpFee


Builder.load_string('''

<TokenTxDialog>
    id: popup
    title: _('Token Transaction')
    is_mine: True
    token_name: ''
    token_symbol: ''
    date_str: ''
    date_label:''
    amount_str: ''
    tx_hash: ''
    status_str: ''
    token_tx_str: ''
    to_addr: ''
    BoxLayout:
        orientation: 'vertical'
        ScrollView:
            scroll_type: ['bars', 'content']
            bar_width: '25dp'
            GridLayout:
                height: self.minimum_height
                size_hint_y: None
                cols: 1
                spacing: '10dp'
                padding: '10dp'
                GridLayout:
                    height: self.minimum_height
                    size_hint_y: None
                    cols: 1
                    spacing: '10dp'
                    BoxLabel:
                        text: _('Token')
                        value: root.token_name
                    BoxLabel:
                        text: _('Status')
                        value: root.status_str
                    BoxLabel:
                        text: root.date_label
                        value: root.date_str
                    BoxLabel:
                        text: (_('Amount sent ') if root.is_mine else _('Amount received ')) + root.token_symbol
                        value: root.amount_str
                TopLabel:
                    text: _('Transaction ID') + ':' if root.tx_hash else ''
                TxHashLabel:
                    data: root.tx_hash
                    name: _('Transaction ID')
                TopLabel:
                    text: _('Token Transaction') + ':' if root.token_tx_str else ''
                TokenLabel:
                    data: root.token_tx_str
                    name: _('Token Transaction')
                    
        Widget:
            size_hint: 1, 0.1

        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                id: action_button
                size_hint: 0.5, None
                height: '48dp'
                text: ''
                disabled: True
                opacity: 0
                on_release: root.on_action_button_clicked()
            IconButton:
                size_hint: 0.5, None
                height: '48dp'
                icon: 'atlas://electrum/gui/kivy/theming/light/qrcode'
                on_release: root.show_qr()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.dismiss()
''')


class TokenTxDialog(Factory.Popup):

    def __init__(self, app, token_tx, token, amount, from_addr, to_addr):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.token_tx = token_tx
        self.token = token
        self.token_name = token.name
        self.token_symbol = token.symbol
        self.amount = amount
        self.token_tx_str = from_addr + " -> " + to_addr

    def on_open(self):
        self.update()

    def show_qr(self):
        from electrum.bitcoin import base_encode, bfh
        raw_tx = str(self.token_tx)
        text = bfh(raw_tx)
        text = base_encode(text, base=43)
        self.app.qr_dialog(_("Raw Token Transaction"), text, text_for_clipboard=raw_tx)

    def update(self):
        format_amount = self.app.format_token_amount_and_units
        tx_details = self.wallet.get_tx_info(self.token_tx)
        tx_mined_status = tx_details.tx_mined_status
        exp_n = tx_details.mempool_depth_bytes
        amount = self.amount
        conf = '{}'.format(tx_mined_status.conf)
        self.status_str = conf + ' ' + (_('confirmation') if conf == '1' else _('confirmations'))
        self.tx_hash = tx_details.txid or ''
        if tx_mined_status.timestamp:
            self.date_label = _('Date')
            self.date_str = datetime.fromtimestamp(tx_mined_status.timestamp).isoformat(' ')[:-3]
        elif exp_n:
            self.date_label = _('Mempool depth')
            self.date_str = _('{} from tip').format('%.2f MB'%(exp_n/1000000))
        else:
            self.date_label = ''
            self.date_str = ''

        if amount is None:
            self.amount_str = _("Transaction unrelated to your wallet")
        elif amount > 0:
            self.is_mine = False
            self.amount_str = format_amount(amount, self.token.decimals, self.token.symbol)
        else:
            self.is_mine = True
            self.amount_str = format_amount(-amount, self.token.decimals, self.token.symbol)
        self.is_local_tx = tx_mined_status.height == TX_HEIGHT_LOCAL
