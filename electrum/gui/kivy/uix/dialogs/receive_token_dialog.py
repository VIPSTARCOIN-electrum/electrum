from datetime import datetime
from kivy.app import App
from kivy.factory import Factory
from kivy.lang import Builder
from kivy.clock import Clock
from kivy.uix.button import Button
from decimal import Decimal

from electrum.gui.kivy.i18n import _

from electrum.util import profiler, InvalidPassword, InvalidBitcoinURI, InvalidTokenURI, parse_URI, parse_token_URI, NotEnoughFunds


Builder.load_string('''

<ReceiveTokenDialog>
    id: popup
    title: _('Request Token')
    name: ''
    symbol: ''
    bind_addr: ''
    contract_addr: ''
    amount: ''
    is_pr: False

    on_contract_addr:
        popup.on_update_qr()
    on_amount:
        popup.on_update_qr()

    BoxLayout:
        orientation: 'vertical'
        FloatLayout:
            id: bl
            QRCodeWidget:
                id: qr
                size_hint: None, 1
                width: min(self.height, bl.width)
                pos_hint: {'center': (.5, .5)}
                shaded: False
                foreground_color: (0, 0, 0, 0.5) if self.shaded else (0, 0, 0, 0)
                on_touch_down:
                    touch = args[1]
                    if self.collide_point(*touch.pos): self.shaded = not self.shaded
        SendReceiveBlueBottom:
            id: blue_bottom
            size_hint: 1, None
            height: self.minimum_height
            BoxLayout:
                size_hint: 2, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/pen'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.name
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/globe'
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.bind_addr
            CardSeparator:
                opacity: int(not root.is_pr)
                color: blue_bottom.foreground_color
            BoxLayout:
                size_hint: 1, None
                height: blue_bottom.item_height
                spacing: '5dp'
                Image:
                    source: 'atlas://electrum/gui/kivy/theming/light/calculator'
                    opacity: 0.7
                    size_hint: None, None
                    size: '22dp', '22dp'
                    pos_hint: {'center_y': .5}
                BlueButton:
                    text: popup.amount if popup.amount else _('Amount')
                    on_release: Clock.schedule_once(lambda dt: app.token_amount_dialog(popup, root.symbol, 0, False))
        BoxLayout:
            size_hint: 1, None
            height: '48dp'
            Button:
                text: _('Copy')
                on_release: popup.do_copy()
            IconButton:
                size_hint: 0.6, 1
                on_release: popup.do_share()
                icon: 'atlas://electrum/gui/kivy/theming/light/share'
        BoxLayout:
            orientation: 'horizontal'
            size_hint: 1, 0.5
            Button:
                text: 'Close'
                size_hint: 0.5, None
                height: '48dp'
                on_release: popup.dismiss()
''')


class ReceiveTokenDialog(Factory.Popup):

    def __init__(self, app, token):
        Factory.Popup.__init__(self)
        self.app = app
        self.wallet = self.app.wallet
        self.token = token
        self.name = token.name
        self.symbol = token.symbol
        self.decimals = token.decimals
        self.decimals_str = "{}".format(token.decimals)
        self.bind_addr = token.bind_addr
        self.contract_addr = token.contract_addr
        self.to_addr = ''
        self.amount = ''
        self.is_pr = False

    def get_URI(self):
        from electrum.util import create_vip1_uri
        amount = self.amount
        if amount:
            a, u = self.amount.split()
            assert u == self.symbol
            amount = Decimal(a) * pow(10, self.decimals)
        return create_vip1_uri(self.contract_addr, self.bind_addr, amount, self.decimals)

    @profiler
    def update_qr(self):
        uri = self.get_URI()
        qr = self.ids.qr
        qr.set_data(uri)

    def do_share(self):
        uri = self.get_URI()
        self.app.do_share(uri, _("Share VIPS Token Request"))

    def do_copy(self):
        uri = self.get_URI()
        self.app._clipboard.copy(uri)
        self.app.show_info(_('Request copied to clipboard'))

    def on_update_qr(self):
        Clock.schedule_once(lambda dt: self.update_qr())
