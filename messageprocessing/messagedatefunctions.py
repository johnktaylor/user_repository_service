from datetime import datetime
import pytz

class MessageDateFunctions():
    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse an ISO 8601 timestamp string into a timezone-aware datetime object.

        Args:
            timestamp_str (str): The timestamp string to parse.

        Returns:
            datetime: A timezone-aware datetime object.
        """
        try:
            dt = datetime.fromisoformat(timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=pytz.UTC)  # Default to UTC if timezone is missing
            return dt.astimezone(pytz.UTC)  # Convert to UTC for consistency
        except ValueError as e:
            raise e