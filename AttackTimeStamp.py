class AttackTimestamp:
    """TODO: Refactor state variable to a better data struct than string i.e., an effective flag data struct"""

    def __init__(self, epoch_start, epoch_end, ordinal_count):
        self.end_epoch = epoch_end
        self.epoch_window = (epoch_start, epoch_end)
        self.start_ordinal = ordinal_count
        self.end_ordinal = ordinal_count
        self.ordinal_window = (self.start_ordinal, self.end_ordinal)
        """
        function: This is a flag variable to define the state of ordinal window.
        state 1: "uninitialised"
        state 2: "start_found"
        state 3: "end_found"
        """
        self.ordinal_window_state = "uninitialised"
        self.test_end_ordinal = None
        self.test_window = None
    def incrementEndOrdinal(self):
        self.end_ordinal += 1

    def set_start_found_state(self):
        self.ordinal_window_state = "start_found"
        print("start_found. Ordinal is", self.start_ordinal, 'for epoch timestamp', self.epoch_window)

    def set_end_found_state(self):
        self.ordinal_window_state = "end_found_state"
        print("FINISHED WINDOW COMPUTE")
        print("ordinal window is", self.ordinal_window)

    def is_end_epoch(self, input_epoch):
        """return whether input_epoch matches end epoch"""
        if input_epoch == self.epoch_window[1]:
            return True

    def set_end_found_state(self):
        self.ordinal_window_state = "end_found"

    def is_start_found(self):
        if self.ordinal_window_state == "start_found":
            return True

    def set_test_window(self, end_count):
        self.test_window = (self.start_ordinal, end_count)