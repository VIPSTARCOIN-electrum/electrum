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

<ViewTokenDialog>
    id: popup
    title: _('Token Info')
    name: ''
    symbol: ''
    decimals_str: ''
    contract_addr: ''
    bind_addr: ''
    date_str: ''
    date_label:''
    balance_str: ''
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
                        text: _('Name')
                        value: root.name
                    BoxLabel:
                        text: root.symbol + ' ' + _('Balance')
                        value: root.balance_str
                    BoxLabel:
                        text: _('Decimals')
                        value: root.decimals_str
                TopLabel:
                    text: _('Bind Address') + ':' if root.bind_addr else ''
                TokenLabel:
                    data: root.bind_addr
                    name: _('Bind Address')
                TopLabel:
                    text: _('Contract Address') + ':' if root.contract_addr else ''
                TokenLabel:
                    data: root.contract_addr
                    name: _('Contract Address')
                    
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
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Delete Token')
                on_release: 
                    root.do_delete()
                    root.dismiss()
            Button:
                size_hint: 0.5, None
                height: '48dp'
                text: _('Close')
                on_release: root.dismiss()
''')


class ViewTokenDialog(Factory.Popup):

    def __init__(self, app, token):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.name = token.name
        self.symbol = token.symbol
        self.decimals = token.decimals
        self.decimals_str = "{}".format(token.decimals)
        self.balance = token.balance
        self.bind_addr = token.bind_addr
        self.contract_addr = token.contract_addr

    def on_open(self):
        self.update()

    def update(self):
        format_amount = self.app.format_token_amount_and_units
        balance = self.balance
        self.balance_str = format_amount(balance, self.decimals, self.symbol)

    def do_delete(self):
        from .question import Question
        key = "{}_{}".format(self.contract_addr, self.bind_addr)
        print(key)
        def cb(result):
            if result:
                self.app.delete_token(key)
        d = Question(_('Delete {} token?').format(self.name), cb)
        d.open()
