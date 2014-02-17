/**
 * Licensed under the MIT License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *		http://taskscheduler.codeplex.com/license
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
**/

using System;
using Microsoft.Win32.TaskScheduler;

namespace MidPointPasswordFilterInstaller.CustomInstaller
{
    public static class ScheduledTask
    {
        /// <summary>
        /// The name of scheduled task.
        /// </summary>
        private const string taskName = "MidPointPasswordFilterProcessor"; 

        /// <summary>
        /// Create a scheduled task for the password filter processor.
        /// Run every day at midnight.
        /// </summary>
        public static void CreateScheduledTask()
        {
            // Get the service on the local machine
            using (TaskService ts = new TaskService())
            {
                // Create a new task definition and assign properties
                TaskDefinition td = ts.NewTask();
                td.RegistrationInfo.Description = "Commits password changes back to Midpoint";
                
                // Create a trigger that will fire the task at 1am every day
                DateTime start = DateTime.Today + TimeSpan.FromHours(1);
                td.Triggers.Add(new DailyTrigger { StartBoundary = start, DaysInterval = 1 });

                // Create an action that will launch Notepad whenever the trigger fires
                td.Actions.Add(new ExecAction(Constants.processorPath, null, null));

                // Register the task in the root folder
                ts.RootFolder.RegisterTaskDefinition(taskName, td);
            }
        }

        /// <summary>
        /// Remove scheduled task for the password filter processor.
        /// </summary>
        public static void DeleteScheduledTask()
        {
            // Get the service on the local machine
            using (TaskService ts = new TaskService())
            {
                foreach (Task t in ts.RootFolder.Tasks)
                {
                    if (t.Name == taskName)
                    {
                        ts.RootFolder.DeleteTask(taskName);
                        break;
                    }
                }
            }
        }
    }
}
