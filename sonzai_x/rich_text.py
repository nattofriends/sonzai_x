"""
https://api.slack.com/changelog/2019-09-what-they-see-is-what-you-get-and-more-and-less
"""

import logging
import re
from string import Formatter
from string import ascii_lowercase

import arrow
import roman

log = logging.getLogger(__name__)


class Bullet:
    def __init__(self):
        self.counter = 1

    def next(self):
        self.counter += 1

    def marker(self):
        value = self.render()
        self.next()
        return value


class NumericBullet(Bullet):
    def render(self):
        return f"{self.counter}."


class AlphabetBullet(Bullet):
    def render(self):
        return f"{self.render_number(self.counter)}."

    def render_number(self, num):
        return (
            ""
            if num == 0
            else self.render_number(
                (num - 1) // len(ascii_lowercase),
            )
            + ascii_lowercase[(num - 1) % len(ascii_lowercase)]
        )


class LowerRomanBullet(Bullet):
    def render(self):
        return f"{roman.toRoman(self.counter).lower()}."


class ConstantBullet:
    def __init__(self, value):
        self.value = value

    def marker(self):
        return self.value


class RichTextRenderer:

    def __init__(self, get_user, get_conversation, get_usergroup, config):
        self.get_user = get_user
        self.get_conversation = get_conversation
        self.get_usergroup = get_usergroup
        self.config = config

        self.formatter = Formatter()

    def render(self, rich_text_block) -> str:
        result = []

        for element in rich_text_block["elements"]:
            element_result = self.dispatch(element)
            result.append(element_result)

        return "\n".join(result)

    def dispatch(self, element):
        """Gross"""
        renderer = f"render_{element['type']}"
        if hasattr(self, renderer):
            return getattr(self, renderer)(element)

        try:
            raise ValueError(f"Don't know how to render {element['type']}: {element}")
        finally:
            # :grimacing:
            return repr(element)

    def render_rich_text_section(self, section) -> str:
        result = []

        for element in section["elements"]:
            element_result = self.dispatch(element)
            result.append(element_result)

        return "".join(result)

    def render_rich_text_list(self, item_list) -> str:
        result = []

        prefix = ""
        if item_list.get("border,", 0) == 1:
            prefix = "> "
        prefix = prefix + "    " * item_list["indent"]

        if item_list["style"] == "ordered":
            marker = OL_BULLETS[item_list["indent"]]()
        elif item_list["style"] == "bullet":
            marker = ConstantBullet(UL_BULLETS[item_list["indent"]])
        else:
            raise ValueError(f"Unexpected list style `{item_list['style']}`")

        for element in item_list["elements"]:
            element_result = self.dispatch(element)
            result.append(f"{prefix}{marker.marker()} {element_result}")

        return "\n".join(result)

    def render_rich_text_quote(self, quote) -> str:
        result = []

        for element in quote["elements"]:
            element_result = self.dispatch(element)
            result.append(f"> {element_result}")

        return "\n".join(result)

    def render_rich_text_preformatted(self, code) -> str:
        result = []

        for element in code["elements"]:
            element_result = self.dispatch(element)
            result.append(element_result)

        result = "\n".join(result)
        if code.get("border") == 1:
            formatted = f"> ```\n> {result}\n> ```"
        else:
            formatted = f"```\n{result}\n```"

        return formatted

    def _format_style(self, text, style) -> str:
        if not style:
            return text

        if style.get("code"):
            text = f"`{text}`"
        if style.get("bold"):
            text = f"\x02{text}\x02"
        if style.get("italic"):
            text = f"\x1d{text}\x1d"
        if style.get("strike"):
            text = f"\x1e{text}\x1e"

        return text

    def render_text(self, rich_text) -> str:
        text = rich_text["text"].rstrip("\n")
        return self._format_style(text, rich_text.get("style"))

    def render_channel(self, channel) -> str:
        channel_info = self.get_conversation(channel["channel_id"])

        if channel_info:
            text = f'#{channel_info["name"]}'
        else:
            text = f"<#{channel['channel_id']}>"

        return self._format_style(text, channel.get("style"))

    def render_user(self, user) -> str:
        user_info = self.get_user(user["user_id"])

        prefix = "@" if self.config["prepend_at_to_names"] else ""

        if user_info:
            text = f"{prefix}{user_info['name']}"
        else:
            text = f"<@{user['user_id']}>"

        return self._format_style(text, user.get("style"))

    def render_emoji(self, emoji) -> str:
        if "unicode" in emoji:
            codepoints = emoji["unicode"].split("-")
            text = "".join([chr(int(codepoint, base=16)) for codepoint in codepoints])
        else:
            text = f":{emoji['name']}:"

        return self._format_style(text, emoji.get("style"))

    def render_link(self, link) -> str:
        url = link["url"]
        text = link.get("text")
        style = link.get("style")

        scheme = re.search(r"^[a-zA-Z-]+:", url)

        if text and text != url:
            # Exception: bare hostname turned link
            if url[len(scheme.group()) : -len(text)] not in ("", "//"):
                # XXX: Might be nice to not render ellipsized URLs
                text = f"\x1f{text}\x1f ({url})"
        else:
            text = url

        return self._format_style(text, style)

    def render_team(self, team) -> str:
        # TODO: No idea how to get an example of this so don't know how it's supposed to look in the client

        return f"<T{team['team_id']}>"

    def render_usergroup(self, usergroup) -> str:
        usergroup_info = self.get_usergroup(usergroup["usergroup_id"])

        if usergroup_info:
            text = f'@{usergroup_info["name"]}'
        else:
            text = f"@{usergroup['usergroup_id']}"

        return self._format_style(text, usergroup.get("style"))

    def render_date(self, date) -> str:
        # Ignoring fallback - we can render format

        # XXX: LOCAL TIME - we know, deal with it
        date_time = arrow.get(date["timestamp"])

        parts = self.formatter.parse(date["format"])
        fields = set()
        for _, field_name, _, _ in parts:
            fields.add(field_name)

        format_data = {}
        for field in fields:
            format_data[field] = date_time.format(DATE_FIELD_FORMAT[field])

        text = date["format"].format(**format_data)

        if "url" in date:
            text += f" ({date['url']})"

        return self._format_style(text, date.get("style"))

    def render_broadcast(self, broadcast) -> str:
        # Forcibly render as bold (XXX: should do this in text-based rendering too)
        text = f"@{broadcast['range']}"
        style = broadcast.get("style", {})
        style.setdefault("bold", True)

        return self._format_style(text, style)

    # unimplemented: render_color


UL_BULLETS = ["•", "◦", "▪︎", "•", "◦"]
OL_BULLETS = [NumericBullet, AlphabetBullet, LowerRomanBullet, NumericBullet, AlphabetBullet]

DATE_FIELD_FORMAT = {
    "date_num": "YYYY-MM-DD",
    # XXX: Year elision not implemented
    "date": "MMMM Do, YYYY",
    "date_short": "MMM D, YYYY",
    "date_long": "dddd, MMMM Do, YYYY",
    # Eh (not implemented)
    "date_pretty": "MMMM Do, YYYY",
    "date_short_pretty": "MMM D, YYYY",
    "date_long_pretty": "dddd, MMMM Do, YYYY",
    "time": "h:mm A",
    "time_secs": "h:m:ss A",
}
